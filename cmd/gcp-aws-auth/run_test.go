package main

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	testToken = "SECRET-ID-TOKEN.payload.signature"
	testARN   = "arn:aws:iam::123456789012:role/test"
)

var testExpiration = time.Date(2026, 11, 11, 16, 0, 0, 0, time.UTC)

// fakeDeps records how run uses its dependencies.
type fakeDeps struct {
	mu            sync.Mutex
	defaultAuds   []string
	impersonated  [][2]string // principal, audience
	assumeInputs  []assumeRoleInput
	tokenDeadline *time.Time

	defaultToken string
	impToken     string
	tokenErr     error
	out          credentialProcessOutput
	stsErr       error
	// blockToken / blockSTS make the call hang while ignoring its context,
	// like idtoken's metadata-server path.
	blockToken, blockSTS chan struct{}
	entered              chan string
}

func newFakeDeps() *fakeDeps {
	return &fakeDeps{
		defaultToken: testToken,
		impToken:     "IMPERSONATED-" + testToken,
		out: credentialProcessOutput{
			Version: 1, AccessKeyID: "AKIDFAKE", SecretAccessKey: "SECRETFAKE",
			SessionToken: "SESSIONFAKE", Expiration: testExpiration,
		},
		entered: make(chan string, 10),
	}
}

func (f *fakeDeps) deps() deps {
	return deps{
		defaultIDToken: func(ctx context.Context, audience string) (string, error) {
			f.mu.Lock()
			f.defaultAuds = append(f.defaultAuds, audience)
			if dl, ok := ctx.Deadline(); ok {
				f.tokenDeadline = &dl
			}
			f.mu.Unlock()
			f.entered <- "token"
			if f.blockToken != nil {
				<-f.blockToken
			}
			return f.defaultToken, f.tokenErr
		},
		impersonatedIDToken: func(_ context.Context, principal, audience string) (string, error) {
			f.mu.Lock()
			f.impersonated = append(f.impersonated, [2]string{principal, audience})
			f.mu.Unlock()
			f.entered <- "token"
			if f.blockToken != nil {
				<-f.blockToken
			}
			return f.impToken, f.tokenErr
		},
		assumeRole: func(_ context.Context, in assumeRoleInput) (credentialProcessOutput, error) {
			f.mu.Lock()
			f.assumeInputs = append(f.assumeInputs, in)
			f.mu.Unlock()
			f.entered <- "sts"
			if f.blockSTS != nil {
				<-f.blockSTS
			}
			return f.out, f.stsErr
		},
	}
}

func (f *fakeDeps) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.defaultAuds) + len(f.impersonated) + len(f.assumeInputs)
}

func runWith(t *testing.T, ctx context.Context, f *fakeDeps, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(ctx, args, &out, &errb, f.deps())
	return code, out.String(), errb.String()
}

func baseArgs(extra ...string) []string {
	return append([]string{"--role-arn", testARN, "--role-session-name", "sess"}, extra...)
}

// assertNoSecrets fails if stderr carries the ID token or any credential value.
func assertNoSecrets(t *testing.T, stderr string) {
	t.Helper()
	for _, s := range []string{testToken, "SECRET-ID-TOKEN", "SECRETFAKE", "SESSIONFAKE", "AKIDFAKE"} {
		if strings.Contains(stderr, s) {
			t.Errorf("stderr leaks %q: %s", s, stderr)
		}
	}
}

func TestRunUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "--role-arn"},
		{"missing session name", []string{"--role-arn", testARN}, "--role-session-name"},
		{"missing role arn", []string{"--role-session-name", "s"}, "--role-arn"},
		{"blank role arn", []string{"--role-arn", "  ", "--role-session-name", "s"}, "--role-arn"},
		{"unknown flag", baseArgs("--no-such-flag"), "no-such-flag"},
		{"flag without value", baseArgs("--region"), "region"},
		{"duration below range", baseArgs("--duration-seconds", "899"), "out of range"},
		{"duration above range", baseArgs("--duration-seconds", "43201"), "out of range"},
		{"duration negative", baseArgs("--duration-seconds", "-1"), "out of range"},
		{"duration not a number", baseArgs("--duration-seconds", "abc"), "duration-seconds"},
		{"timeout unparsable", baseArgs("--timeout", "abc"), "timeout"},
		// a bare number is the obvious mistake; the message must say what to type
		{"timeout bare number", baseArgs("--timeout", "30"),
			`invalid value "30" for flag -timeout: want a duration with a unit, such as 30s, 2m or 1m30s`},
		{"timeout negative", baseArgs("--timeout", "-5s"), "negative"},
		{"empty audience", baseArgs("--audience", ""), "audience"},
		{"blank service account", baseArgs("--impersonate-service-account", "  "), "--impersonate-service-account"},
		{"region with spaces", baseArgs("--region", "eu west 1"), `--region "eu west 1"`},
		{"region with underscore", baseArgs("--region", "eu_west_1"), "--region"},
		{"region with leading hyphen", baseArgs("--region", "-eu-west-1"), "--region"},
		{"region with empty label", baseArgs("--region", "eu..west"), "--region"},
		{"region label too long", baseArgs("--region", strings.Repeat("a", 64)), "--region"},
		{"trailing positional", baseArgs("oops"), `"oops"`},
		// Go's flag package stops at the first positional argument: without
		// this check the session name after it would be dropped silently.
		{"positional before a flag", []string{"--role-arn", testARN, "oops", "--role-session-name", "s"}, `"oops"`},
		{"positional after --version", []string{"--version", "extra"}, `"extra"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDeps()
			code, stdout, stderr := runWith(t, t.Context(), f, tc.args...)
			if code != 2 {
				t.Errorf("exit code %d, want 2", code)
			}
			if stdout != "" {
				t.Errorf("stdout not empty: %q", stdout)
			}
			if !strings.Contains(stderr, tc.want) || !strings.HasPrefix(stderr, "gcp-aws-auth: ") {
				t.Errorf("stderr %q does not name the problem (%q)", stderr, tc.want)
			}
			if n := f.calls(); n != 0 {
				t.Errorf("%d dependency calls before validation finished", n)
			}
		})
	}
}

func TestRunAcceptsBoundaryValues(t *testing.T) {
	for _, extra := range [][]string{
		{"--duration-seconds", "900"},
		{"--duration-seconds", "43200"},
		{"--duration-seconds", "0"},
		{"--timeout", "0"},
		{"-timeout=90s", "-region=eu-west-1"},
		{"--region", "us-gov-west-1"},
		{"--region", "fips-us-east-1"},
		{"--region", strings.Repeat("a", 63)},
	} {
		code, _, stderr := runWith(t, t.Context(), newFakeDeps(), baseArgs(extra...)...)
		if code != 0 {
			t.Errorf("%v: exit %d, stderr %q", extra, code, stderr)
		}
	}
}

func TestRunHelp(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		f := newFakeDeps()
		code, stdout, stderr := runWith(t, t.Context(), f, arg)
		if code != 0 || stderr != "" {
			t.Errorf("%s: exit %d, stderr %q", arg, code, stderr)
		}
		// Users' AWS trust policies condition on this audience: pin the literal.
		for _, want := range []string{`(default "sts.amazonaws.com")`, "(default 1m0s)", "such as 30s, 2m", "default of 3600"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%s: usage lacks %s", arg, want)
			}
		}
		for _, name := range []string{"role-arn", "role-session-name", "impersonate-service-account",
			"audience", "region", "duration-seconds", "timeout", "version"} {
			if !strings.Contains(stdout, "-"+name) {
				t.Errorf("%s: usage does not document --%s", arg, name)
			}
		}
		if f.calls() != 0 {
			t.Errorf("%s: dependencies called", arg)
		}
	}
}

func TestRunVersion(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "9.9.9"
	code, stdout, stderr := runWith(t, t.Context(), newFakeDeps(), "--version")
	if code != 0 || stdout != "9.9.9\n" || stderr != "" {
		t.Errorf("injected version: exit %d stdout %q stderr %q", code, stdout, stderr)
	}

	version = "dev"
	_, stdout, _ = runWith(t, t.Context(), newFakeDeps(), "--version")
	if stdout != versionString()+"\n" || strings.Count(stdout, "\n") != 1 {
		t.Errorf("dev build printed %q", stdout)
	}
}

func TestResolveVersion(t *testing.T) {
	withMain := func(v string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Path: "example.com/m", Version: v}}
	}
	tests := []struct {
		name     string
		injected string
		info     *debug.BuildInfo
		ok       bool
		want     string
	}{
		{"ldflags wins over module version", "v1.2.3", withMain("v0.9.0"), true, "v1.2.3"},
		{"VCS pseudo-version or module version", "dev", withMain("v0.9.0"), true, "v0.9.0"},
		{"devel build", "dev", withMain("(devel)"), true, "dev"},
		{"empty module version", "dev", withMain(""), true, "dev"},
		{"no build info", "dev", nil, false, "dev"},
		{"empty injected", "", withMain("v0.9.0"), true, "v0.9.0"},
	}
	for _, tc := range tests {
		if got := resolveVersion(tc.injected, tc.info, tc.ok); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestRunSuccessExactOutput(t *testing.T) {
	f := newFakeDeps()
	code, stdout, stderr := runWith(t, t.Context(), f, baseArgs()...)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	want := `{
  "Version": 1,
  "AccessKeyId": "AKIDFAKE",
  "SecretAccessKey": "SECRETFAKE",
  "SessionToken": "SESSIONFAKE",
  "Expiration": "2026-11-11T16:00:00Z"
}
`
	if stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", stdout, want)
	}
	if stderr != "" {
		t.Errorf("stderr not empty on success: %q", stderr)
	}
}

func TestRunTokenSourceSelection(t *testing.T) {
	t.Run("default audience", func(t *testing.T) {
		f := newFakeDeps()
		if code, _, stderr := runWith(t, t.Context(), f, baseArgs()...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		// Contract value: AWS trust policies condition on it. Literal on purpose.
		if len(f.defaultAuds) != 1 || f.defaultAuds[0] != "sts.amazonaws.com" {
			t.Errorf("default audience %v, want sts.amazonaws.com", f.defaultAuds)
		}
	})
	t.Run("default credentials", func(t *testing.T) {
		f := newFakeDeps()
		if code, _, stderr := runWith(t, t.Context(), f, baseArgs("--audience", "my-aud")...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if len(f.impersonated) != 0 || len(f.defaultAuds) != 1 || f.defaultAuds[0] != "my-aud" {
			t.Errorf("default=%v impersonated=%v", f.defaultAuds, f.impersonated)
		}
		if f.assumeInputs[0].webIdentityToken != f.defaultToken {
			t.Errorf("STS got token %q", f.assumeInputs[0].webIdentityToken)
		}
	})
	t.Run("impersonation", func(t *testing.T) {
		f := newFakeDeps()
		sa := "deployer@proj.iam.gserviceaccount.com"
		if code, _, stderr := runWith(t, t.Context(), f, baseArgs("--impersonate-service-account", sa)...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if len(f.defaultAuds) != 0 || len(f.impersonated) != 1 || f.impersonated[0] != [2]string{sa, "sts.amazonaws.com"} {
			t.Errorf("default=%v impersonated=%v", f.defaultAuds, f.impersonated)
		}
		if f.assumeInputs[0].webIdentityToken != f.impToken {
			t.Errorf("STS got token %q", f.assumeInputs[0].webIdentityToken)
		}
	})
	t.Run("impersonation with custom audience", func(t *testing.T) {
		f := newFakeDeps()
		sa := "deployer@proj.iam.gserviceaccount.com"
		if code, _, stderr := runWith(t, t.Context(), f,
			baseArgs("--impersonate-service-account", sa, "--audience", "custom-aud")...); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
		if len(f.defaultAuds) != 0 || len(f.impersonated) != 1 || f.impersonated[0] != [2]string{sa, "custom-aud"} {
			t.Errorf("default=%v impersonated=%v", f.defaultAuds, f.impersonated)
		}
	})
}

func TestRunPassesSTSParameters(t *testing.T) {
	f := newFakeDeps()
	args := []string{"--role-arn", testARN, "--role-session-name", "my-session",
		"--region", "ap-southeast-2", "--duration-seconds", "7200"}
	if code, _, stderr := runWith(t, t.Context(), f, args...); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := assumeRoleInput{roleARN: testARN, roleSessionName: "my-session", webIdentityToken: testToken,
		region: "ap-southeast-2", durationSeconds: 7200}
	if len(f.assumeInputs) != 1 || f.assumeInputs[0] != want {
		t.Errorf("assumeRole inputs %+v, want %+v", f.assumeInputs, want)
	}

	f = newFakeDeps()
	runWith(t, t.Context(), f, baseArgs()...)
	if in := f.assumeInputs[0]; in.region != "" || in.durationSeconds != 0 {
		t.Errorf("defaults: region %q duration %d, want empty and 0", in.region, in.durationSeconds)
	}
}

func TestRunFailures(t *testing.T) {
	unsupported := &unsupportedCredentialsError{err: errors.New(`idtoken: unsupported credentials type: "authorized_user"`)}
	tests := []struct {
		name      string
		setup     func(*fakeDeps)
		args      []string
		want      []string
		wantHint  bool
		wantNoSTS bool
	}{
		{"default token error", func(f *fakeDeps) { f.tokenErr = errors.New("metadata unreachable") },
			nil, []string{"failed to get Google ID token", "metadata unreachable"}, false, true},
		{"impersonation error", func(f *fakeDeps) { f.tokenErr = errors.New("permission denied") },
			[]string{"--impersonate-service-account", "sa@p.iam.gserviceaccount.com"},
			[]string{"failed to get Google ID token", "permission denied"}, false, true},
		{"empty token", func(f *fakeDeps) { f.defaultToken = "" }, nil, []string{"empty"}, false, true},
		{"user credentials get a hint", func(f *fakeDeps) { f.tokenErr = unsupported }, nil,
			[]string{"unsupported credentials type", "roles/iam.serviceAccountOpenIdTokenCreator", "roles/iam.serviceAccountTokenCreator"},
			true, true},
		{"STS error", func(f *fakeDeps) { f.stsErr = errors.New("AccessDenied: not authorized") },
			nil, []string{"STS AssumeRoleWithWebIdentity failed", "AccessDenied"}, false, false},
		{"AWS configuration is not an STS failure",
			func(f *fakeDeps) {
				f.stsErr = &awsConfigError{err: errors.New("failed to get shared config profile, nope")}
			},
			nil, []string{"gcp-aws-auth: loading AWS configuration: failed to get shared config profile, nope"}, false, false},
		{"STS without credentials", func(f *fakeDeps) { f.stsErr = errors.New("STS response contains no credentials") },
			nil, []string{"no credentials"}, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDeps()
			tc.setup(f)
			code, stdout, stderr := runWith(t, t.Context(), f, baseArgs(tc.args...)...)
			if code != 1 {
				t.Errorf("exit %d, want 1", code)
			}
			if stdout != "" {
				t.Errorf("stdout not empty on failure: %q", stdout)
			}
			for _, w := range tc.want {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr %q lacks %q", stderr, w)
				}
			}
			if got := strings.Contains(stderr, "--impersonate-service-account"); got != tc.wantHint {
				t.Errorf("hint present=%v, want %v: %q", got, tc.wantHint, stderr)
			}
			if f.stsErr != nil && strings.Contains(stderr, "STS AssumeRoleWithWebIdentity failed") !=
				!strings.Contains(stderr, "loading AWS configuration") {
				t.Errorf("STS failure label wrong: %q", stderr)
			}
			if tc.wantNoSTS && len(f.assumeInputs) != 0 {
				t.Error("STS called without a token")
			}
			assertNoSecrets(t, stderr)
		})
	}
}

func TestTruncateDiagnostic(t *testing.T) {
	if got := truncateDiagnostic("short", 100); got != "short" {
		t.Errorf("short message changed: %q", got)
	}
	// Every alignment of the cut against 2- and 4-byte runes.
	inputs := []string{strings.Repeat("x", 5000)}
	for pad := range 4 {
		inputs = append(inputs,
			strings.Repeat("x", pad)+strings.Repeat("é", 3000),
			strings.Repeat("x", pad)+strings.Repeat("😀", 2000))
	}
	for _, s := range inputs {
		got := truncateDiagnostic(s, 4096)
		if len(got) > 4096 || !strings.HasSuffix(got, " [... truncated]") || !utf8.ValidString(got) {
			t.Errorf("len %d, suffix ok %v, valid UTF-8 %v",
				len(got), strings.HasSuffix(got, " [... truncated]"), utf8.ValidString(got))
		}
		if len(got) < 4096-4 {
			t.Errorf("cut too much: %d bytes kept", len(got))
		}
	}
}

// TestRunCapsDiagnostics: a library error can embed a whole response body;
// what one failure prints stays within 4 KiB, the hint included.
func TestRunCapsDiagnostics(t *testing.T) {
	body := strings.Repeat("<html>proxy error é ", 60000) // ~1.2 MB
	for _, tc := range []struct {
		name     string
		err      error
		wantHint bool
	}{
		{"plain error", errors.New("impersonate: status code 502: " + body), false},
		{"error with hint", &unsupportedCredentialsError{err: errors.New("idtoken: unsupported credentials type: " + body)}, true},
	} {
		f := newFakeDeps()
		f.tokenErr = tc.err
		code, stdout, stderr := runWith(t, t.Context(), f, baseArgs()...)
		if code != 1 || stdout != "" {
			t.Errorf("%s: exit %d stdout %q", tc.name, code, stdout)
		}
		if len(stderr) > 4096 || !utf8.ValidString(stderr) || !strings.Contains(stderr, " [... truncated]\n") {
			t.Errorf("%s: %d bytes, valid UTF-8 %v, marker %v", tc.name, len(stderr),
				utf8.ValidString(stderr), strings.Contains(stderr, " [... truncated]\n"))
		}
		if tc.wantHint && !strings.HasSuffix(stderr, "roles/iam.serviceAccountTokenCreator).\n") {
			t.Errorf("%s: hint lost: ...%q", tc.name, stderr[max(len(stderr)-200, 0):])
		}
	}

	// Usage errors echo user input; they are capped too.
	code, _, stderr := runWith(t, t.Context(), newFakeDeps(), baseArgs("--region", strings.Repeat("é", 5000))...)
	if code != 2 || len(stderr) > 4096 || !strings.Contains(stderr, " [... truncated]") {
		t.Errorf("usage error: exit %d, %d bytes", code, len(stderr))
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

func TestRunWriteError(t *testing.T) {
	var errb bytes.Buffer
	code := run(t.Context(), baseArgs(), failingWriter{}, &errb, newFakeDeps().deps())
	if code != 1 || !strings.Contains(errb.String(), "broken pipe") {
		t.Errorf("exit %d, stderr %q", code, errb.String())
	}
	assertNoSecrets(t, errb.String())
}

// hangLimit only detects a run that never returns; no test asserts timing
// against it.
const hangLimit = 30 * time.Second

// runAsync runs run in a goroutine and fails the test if it hangs.
func runAsync(t *testing.T, ctx context.Context, f *fakeDeps, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	type res struct {
		code           int
		stdout, stderr string
	}
	ch := make(chan res, 1)
	go func() {
		var out, errb bytes.Buffer
		code := run(ctx, args, &out, &errb, f.deps())
		ch <- res{code, out.String(), errb.String()}
	}()
	select {
	case r := <-ch:
		return r.code, r.stdout, r.stderr
	case <-time.After(hangLimit):
		t.Fatal("run did not return")
		return 0, "", ""
	}
}

// waitEntered blocks until the fake reports that step ("token" or "sts") is
// in flight.
func waitEntered(t *testing.T, f *fakeDeps, step string) {
	t.Helper()
	for {
		select {
		case got := <-f.entered:
			if got == step {
				return
			}
		case <-time.After(hangLimit):
			t.Fatalf("step %q never started", step)
		}
	}
}

// TestRunTimeoutBoundsCallsThatIgnoreContext exercises the real --timeout
// wiring against calls that never return. Which step the deadline catches
// depends on scheduling, so the assertions hold for either step.
func TestRunTimeoutBoundsCallsThatIgnoreContext(t *testing.T) {
	stageMessage := regexp.MustCompile(`^gcp-aws-auth: timed out after 50ms while ` +
		`(fetching the Google ID token|calling STS AssumeRoleWithWebIdentity) \(see --timeout\)\n$`)
	tests := []struct {
		name  string
		setup func(f *fakeDeps, release chan struct{})
	}{
		{"token fetch hangs", func(f *fakeDeps, r chan struct{}) { f.blockToken = r }},
		{"STS call hangs", func(f *fakeDeps, r chan struct{}) { f.blockSTS = r }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDeps()
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			tc.setup(f, release)
			code, stdout, stderr := runAsync(t, t.Context(), f, baseArgs("--timeout", "50ms")...)
			if code != 1 || stdout != "" {
				t.Errorf("exit %d, stdout %q", code, stdout)
			}
			if !stageMessage.MatchString(stderr) {
				t.Errorf("stderr %q does not match %s", stderr, stageMessage)
			}
			assertNoSecrets(t, stderr)
		})
	}
}

// TestRunCancellationNamesTheStep makes the order explicit: the call is in
// flight first, then the run is canceled with a timeout or signal cause.
func TestRunCancellationNamesTheStep(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		block   func(f *fakeDeps, release chan struct{})
		step    string
		cause   error
		wantErr string
	}{
		{"timeout during default token", nil,
			func(f *fakeDeps, r chan struct{}) { f.blockToken = r }, "token", &timeoutError{2 * time.Second},
			"gcp-aws-auth: timed out after 2s while fetching the Google ID token (see --timeout)\n"},
		{"timeout during impersonation", []string{"--impersonate-service-account", "sa@p.iam.gserviceaccount.com"},
			func(f *fakeDeps, r chan struct{}) { f.blockToken = r }, "token", &timeoutError{2 * time.Second},
			"gcp-aws-auth: timed out after 2s while fetching the impersonated Google ID token (see --timeout)\n"},
		{"timeout during STS", nil,
			func(f *fakeDeps, r chan struct{}) { f.blockSTS = r }, "sts", &timeoutError{2 * time.Second},
			"gcp-aws-auth: timed out after 2s while calling STS AssumeRoleWithWebIdentity (see --timeout)\n"},
		// main cancels through signal.NotifyContext with a cause like this one.
		{"signal during token", nil,
			func(f *fakeDeps, r chan struct{}) { f.blockToken = r }, "token", errors.New("terminated signal received"),
			"gcp-aws-auth: interrupted (terminated signal received) while fetching the Google ID token\n"},
		{"signal during STS", nil,
			func(f *fakeDeps, r chan struct{}) { f.blockSTS = r }, "sts", errors.New("interrupt signal received"),
			"gcp-aws-auth: interrupted (interrupt signal received) while calling STS AssumeRoleWithWebIdentity\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeDeps()
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			tc.block(f, release)
			ctx, cancel := context.WithCancelCause(t.Context())
			t.Cleanup(func() { cancel(nil) })
			go func() {
				waitEntered(t, f, tc.step)
				cancel(tc.cause)
			}()
			// --timeout 0: the only cancellation is the one above.
			code, stdout, stderr := runAsync(t, ctx, f, baseArgs(append(tc.args, "--timeout", "0")...)...)
			if code != 1 || stdout != "" {
				t.Errorf("exit %d, stdout %q", code, stdout)
			}
			if stderr != tc.wantErr {
				t.Errorf("stderr %q, want %q", stderr, tc.wantErr)
			}
		})
	}
}

// TestRunTimeoutReportedWhenCallReturnsContextError: a call that honors ctx
// returns its context error; the report is still about the timeout.
func TestRunTimeoutReportedWhenCallReturnsContextError(t *testing.T) {
	f := newFakeDeps()
	d := f.deps()
	d.assumeRole = func(ctx context.Context, _ assumeRoleInput) (credentialProcessOutput, error) {
		<-ctx.Done()
		return credentialProcessOutput{}, ctx.Err()
	}
	var out, errb bytes.Buffer
	code := run(t.Context(), baseArgs("--timeout", "20ms"), &out, &errb, d)
	if code != 1 || out.Len() != 0 || !strings.HasPrefix(errb.String(), "gcp-aws-auth: timed out after 20ms while ") {
		t.Errorf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

func TestReportFailurePrefersCancellationCause(t *testing.T) {
	expired, cancel := context.WithTimeoutCause(t.Context(), -time.Second, &timeoutError{2 * time.Second})
	defer cancel()
	var errb bytes.Buffer
	code := reportFailure(expired, &errb, stageSTS, context.DeadlineExceeded)
	if want := "timed out after 2s while calling STS AssumeRoleWithWebIdentity"; code != 1 || !strings.Contains(errb.String(), want) {
		t.Errorf("exit %d stderr %q, want %q", code, errb.String(), want)
	}

	errb.Reset()
	code = reportFailure(t.Context(), &errb, stageSTS, errors.New("boom"))
	if code != 1 || errb.String() != "gcp-aws-auth: boom\n" {
		t.Errorf("live context: exit %d stderr %q", code, errb.String())
	}
}

func TestRunTimeoutDeadline(t *testing.T) {
	t.Run("default is one minute", func(t *testing.T) {
		f := newFakeDeps()
		before := time.Now()
		runWith(t, t.Context(), f, baseArgs()...)
		after := time.Now()
		if f.tokenDeadline == nil {
			t.Fatal("no deadline by default")
		}
		// The deadline is set between before and after, one minute ahead.
		if dl := *f.tokenDeadline; dl.Before(before.Add(time.Minute)) || dl.After(after.Add(time.Minute)) {
			t.Errorf("deadline %s not one minute after the run started (%s..%s)", dl, before, after)
		}
	})
	t.Run("zero disables", func(t *testing.T) {
		f := newFakeDeps()
		if code, _, _ := runWith(t, t.Context(), f, baseArgs("--timeout", "0")...); code != 0 {
			t.Fatal("run failed")
		}
		if f.tokenDeadline != nil {
			t.Errorf("deadline set with --timeout 0: %s", f.tokenDeadline)
		}
	})
}
