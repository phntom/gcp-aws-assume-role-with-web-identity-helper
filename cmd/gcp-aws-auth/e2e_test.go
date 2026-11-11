package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// runMainEnv makes the test binary behave as the real program: the
// end-to-end tests re-execute it with this variable set.
const runMainEnv = "GCP_AWS_AUTH_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

type process struct {
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
}

// startProgram re-executes the test binary as the program with a minimal,
// fully explicit environment pointing at the given fakes.
func startProgram(t *testing.T, md *fakeMetadata, sts *fakeSTS, args ...string) *process {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	p := &process{}
	// The context only guards against a hung child; tests signal it themselves.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	p.cmd = exec.CommandContext(ctx, exe, args...) //nolint:gosec // G204: re-executes this test binary with test-chosen arguments
	p.cmd.Env = []string{
		runMainEnv + "=1",
		"HOME=" + home,
		"GOCOVERDIR=" + t.TempDir(), // a -cover build would otherwise warn on stderr
		"GCE_METADATA_HOST=" + md.host(),
		"AWS_ENDPOINT_URL_STS=" + sts.URL,
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_CONFIG_FILE=" + home + "/aws-config",
		"AWS_SHARED_CREDENTIALS_FILE=" + home + "/aws-credentials",
	}
	p.cmd.Stdout, p.cmd.Stderr = &p.stdout, &p.stderr
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *process) wait(t *testing.T) int {
	t.Helper()
	err := p.cmd.Wait()
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode() // -1 when killed by a signal
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0
}

func TestEndToEndSuccess(t *testing.T) {
	md, sts := newFakeMetadata(t), newFakeSTS(t)
	p := startProgram(t, md, sts, "--role-arn", "arn:aws:iam::123456789012:role/ok",
		"--role-session-name", "e2e", "--duration-seconds", "7200")
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, p.stderr.String())
	}
	if p.stderr.Len() != 0 {
		t.Errorf("stderr not empty: %q", p.stderr.String())
	}
	want := `{
  "Version": 1,
  "AccessKeyId": "` + fakeAccessKeyID + `",
  "SecretAccessKey": "` + fakeSecretAccessKey + `",
  "SessionToken": "` + fakeSessionToken + `",
  "Expiration": "2030-01-02T05:04:05Z"
}
`
	if p.stdout.String() != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", p.stdout.String(), want)
	}
	reqs := sts.recorded()
	if len(reqs) != 1 {
		t.Fatalf("%d STS requests", len(reqs))
	}
	// The default audience is contract (AWS trust policies condition on it),
	// so it is pinned as a literal, not through the production constant.
	if got := reqs[0].form.Get("WebIdentityToken"); got != fakeJWT("sts.amazonaws.com") {
		t.Errorf("STS received token %q, want the metadata server's token for sts.amazonaws.com", got)
	}
	if reqs[0].header.Get("Authorization") != "" {
		t.Error("STS request is signed")
	}
	if reqs[0].form.Get("DurationSeconds") != "7200" {
		t.Errorf("DurationSeconds %q", reqs[0].form.Get("DurationSeconds"))
	}
}

func TestEndToEndFailures(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantCode int
		want     string
		noNet    bool
	}{
		{"usage error before any network", []string{"--role-arn", "arn:aws:iam::1:role/ok", "oops", "--role-session-name", "s"}, 2, `"oops"`, true},
		{"invalid region before any network", []string{"--role-arn", "arn:aws:iam::1:role/ok", "--role-session-name", "s",
			"--region", "eu west 1"}, 2, `--region "eu west 1"`, true},
		{"access denied", []string{"--role-arn", "arn:aws:iam::1:role/deny", "--role-session-name", "s"}, 1, "AccessDenied", false},
		{"no credentials in response", []string{"--role-arn", "arn:aws:iam::1:role/nocreds", "--role-session-name", "s"}, 1, "no credentials", false},
		{"hanging metadata call", []string{"--role-arn", "arn:aws:iam::1:role/ok", "--role-session-name", "s",
			"--audience", "hang", "--timeout", "300ms"}, 1, "timed out after 300ms while fetching the Google ID token", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			md, sts := newFakeMetadata(t), newFakeSTS(t)
			start := time.Now()
			p := startProgram(t, md, sts, tc.args...)
			code := p.wait(t)
			if code != tc.wantCode {
				t.Errorf("exit %d, want %d; stderr %q", code, tc.wantCode, p.stderr.String())
			}
			if p.stdout.Len() != 0 {
				t.Errorf("stdout not empty: %q", p.stdout.String())
			}
			stderr := p.stderr.String()
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr %q lacks %q", stderr, tc.want)
			}
			if strings.Contains(stderr, "goroutine ") || strings.Contains(stderr, "panic") {
				t.Errorf("stack trace: %s", stderr)
			}
			for _, r := range sts.recorded() {
				if tok := r.form.Get("WebIdentityToken"); tok != "" && strings.Contains(stderr, tok) {
					t.Error("stderr leaks the ID token")
				}
			}
			if tc.noNet && (len(md.recorded()) != 0 || len(sts.recorded()) != 0) {
				t.Error("network contacted before argument validation")
			}
			if elapsed := time.Since(start); elapsed > 10*time.Second {
				t.Errorf("took %s", elapsed)
			}
		})
	}
}

func TestEndToEndSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Process.Signal cannot deliver SIGTERM on Windows")
	}
	md, sts := newFakeMetadata(t), newFakeSTS(t)
	p := startProgram(t, md, sts, "--role-arn", "arn:aws:iam::1:role/slow", "--role-session-name", "s")
	select {
	case <-sts.arrived:
	case <-time.After(15 * time.Second):
		t.Fatalf("program never reached STS; stderr %q", p.stderr.String())
	}
	sent := time.Now()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	code := p.wait(t)
	if elapsed := time.Since(sent); elapsed > 3*time.Second {
		t.Errorf("exit took %s after SIGTERM", elapsed)
	}
	// 1 means the program handled the signal; -1 would mean it was killed.
	if code != 1 {
		t.Errorf("exit %d, want 1", code)
	}
	if p.stdout.Len() != 0 {
		t.Errorf("stdout not empty: %q", p.stdout.String())
	}
	// Only our own wording: the signal's description comes from the Go runtime.
	if stderr := p.stderr.String(); !strings.Contains(stderr, "gcp-aws-auth: interrupted (") ||
		!strings.Contains(stderr, ") while calling STS AssumeRoleWithWebIdentity") ||
		strings.Contains(stderr, "goroutine ") {
		t.Errorf("stderr %q", stderr)
	}
}

// TestEndToEndQuietWithMalformedDateHeader: the SDK logs a warning when a
// response's Date header does not parse. Its logger must not reach stderr,
// which has to stay empty on success.
func TestEndToEndQuietWithMalformedDateHeader(t *testing.T) {
	md, sts := newFakeMetadata(t), newFakeSTS(t)
	p := startProgram(t, md, sts, "--role-arn", "arn:aws:iam::1:role/baddate", "--role-session-name", "s")
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, p.stderr.String())
	}
	if p.stderr.Len() != 0 {
		t.Errorf("stderr not empty on success: %q", p.stderr.String())
	}
	if !strings.Contains(p.stdout.String(), `"AccessKeyId": "`+fakeAccessKeyID+`"`) {
		t.Errorf("stdout %q", p.stdout.String())
	}
	if reqs := sts.recorded(); len(reqs) != 1 {
		t.Errorf("%d STS requests", len(reqs))
	}
}

// TestEndToEndOutputIsOneJSONDocument guards stdout purity for the AWS
// SDKs: exactly one JSON object and nothing else.
func TestEndToEndOutputIsOneJSONDocument(t *testing.T) {
	md, sts := newFakeMetadata(t), newFakeSTS(t)
	p := startProgram(t, md, sts, "--role-arn", "arn:aws:iam::1:role/ok", "--role-session-name", "s")
	if code := p.wait(t); code != 0 {
		t.Fatalf("exit %d: %s", code, p.stderr.String())
	}
	dec := json.NewDecoder(&p.stdout)
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if dec.More() {
		t.Error("trailing data after the JSON document")
	}
	if doc["Version"] != float64(1) || len(doc) != 5 {
		t.Errorf("document %v", doc)
	}
}
