package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// credentialProcessOutput is the document AWS credential_process expects.
type credentialProcessOutput struct {
	Version         int       `json:"Version"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

// assumeRoleInput is everything the STS call needs.
type assumeRoleInput struct {
	roleARN          string
	roleSessionName  string
	webIdentityToken string
	region           string // from --region; empty means SDK resolution, then us-east-1
	durationSeconds  int32  // 0 means "not sent"
}

// deps are the side-effecting operations run depends on; tests substitute fakes.
type deps struct {
	defaultIDToken      func(ctx context.Context, audience string) (string, error)
	impersonatedIDToken func(ctx context.Context, targetPrincipal, audience string) (string, error)
	assumeRole          func(ctx context.Context, in assumeRoleInput) (credentialProcessOutput, error)
}

const (
	stageDefaultToken  = "fetching the Google ID token"
	stageImpersonated  = "fetching the impersonated Google ID token"
	stageSTS           = "calling STS AssumeRoleWithWebIdentity"
	stageWritingOutput = "writing the credential document"
)

// timeoutError is the cancellation cause recorded when --timeout expires.
type timeoutError struct{ d time.Duration }

func (e *timeoutError) Error() string { return fmt.Sprintf("timed out after %s", e.d) }

// run executes the program and returns its exit code. stdout receives the
// credential document only after every step has succeeded.
func run(ctx context.Context, args []string, stdout, stderr io.Writer, d deps) int {
	opts, err := parseArgs(args)
	switch {
	case errors.Is(err, flag.ErrHelp):
		var buf bytes.Buffer
		printUsage(&buf)
		return writeStdout(stdout, stderr, buf.Bytes(), "usage")
	case err != nil:
		warnf(stderr, "%s\nRun '%s --help' for usage.\n",
			truncateDiagnostic(progName+": "+err.Error(), maxDiagnosticBytes-100), progName)
		return 2
	case opts.showVersion:
		return writeStdout(stdout, stderr, []byte(versionString()+"\n"), "version")
	}

	if opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeoutCause(ctx, opts.timeout, &timeoutError{opts.timeout})
		defer cancel()
	}

	// Some library calls (the metadata-server and impersonation token
	// fetches) ignore the context, so the work runs in its own goroutine and
	// the run as a whole stops waiting when the context ends. The process
	// exits right after, which abandons any call still in flight.
	type result struct {
		out credentialProcessOutput
		err error
	}
	// The first stage is recorded before the worker starts, so a limit that
	// expires immediately still names a real step.
	var stage atomic.Value
	stage.Store(stageDefaultToken)
	if opts.impersonateSA != "" {
		stage.Store(stageImpersonated)
	}
	done := make(chan result, 1)
	go func() {
		out, err := obtainCredentials(ctx, opts, d, &stage)
		done <- result{out, err}
	}()

	var out credentialProcessOutput
	select {
	case r := <-done:
		if r.err != nil {
			return reportFailure(ctx, stderr, stage.Load().(string), r.err)
		}
		out = r.out
	case <-ctx.Done():
		return reportCancelled(ctx, stderr, stage.Load().(string))
	}

	stage.Store(stageWritingOutput)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writeCredentialDocument(stdout, &out)
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			warnf(stderr, "%s: %v\n", progName, err)
			return 1
		}
		return 0
	case <-ctx.Done():
		return reportCancelled(ctx, stderr, stageWritingOutput)
	}
}

// writeCredentialDocument emits the credential JSON in one call. It runs in a
// goroutine because a Writer can block just like a network call.
func writeCredentialDocument(w io.Writer, out *credentialProcessOutput) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	// Emitting these credentials on stdout is the purpose of the program.
	if err := enc.Encode(out); err != nil { //nolint:gosec // G117: the credential document is the intended output
		return fmt.Errorf("encoding credentials: %w", err)
	}
	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("writing credentials to stdout: %w", err)
	}
	return nil
}

// writeStdout writes b in one call and reports a failed write as exit 1.
func writeStdout(stdout, stderr io.Writer, b []byte, what string) int {
	if _, err := stdout.Write(b); err != nil {
		warnf(stderr, "%s: writing %s to stdout: %v\n", progName, what, err)
		return 1
	}
	return 0
}

// warnf writes a diagnostic. If stderr itself is broken there is nowhere left
// to report that, so the write error is deliberately dropped.
func warnf(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, format, args...)
}

func obtainCredentials(ctx context.Context, o *options, d deps, stage *atomic.Value) (credentialProcessOutput, error) {
	var (
		token string
		err   error
	)
	if o.impersonateSA != "" {
		token, err = d.impersonatedIDToken(ctx, o.impersonateSA, o.audience)
	} else {
		token, err = d.defaultIDToken(ctx, o.audience)
	}
	if err != nil {
		return credentialProcessOutput{}, fmt.Errorf("failed to get Google ID token: %w", err)
	}
	if token == "" {
		return credentialProcessOutput{}, errors.New("failed to get Google ID token: the token is empty")
	}

	stage.Store(stageSTS)
	out, err := d.assumeRole(ctx, assumeRoleInput{
		roleARN:          o.roleARN,
		roleSessionName:  o.roleSessionName,
		webIdentityToken: token,
		region:           o.region,
		durationSeconds:  o.durationSeconds,
	})
	if _, ok := errors.AsType[*awsConfigError](err); ok {
		return credentialProcessOutput{}, err // STS was never called
	}
	if err != nil {
		return credentialProcessOutput{}, fmt.Errorf("STS AssumeRoleWithWebIdentity failed: %w", err)
	}
	return out, nil
}

// reportFailure reports err, unless the run was canceled meanwhile: a call
// that honors ctx can return its context error just before run sees ctx.Done,
// and then the timeout or signal is the useful diagnostic.
func reportFailure(ctx context.Context, stderr io.Writer, stage string, err error) int {
	if ctx.Err() != nil {
		return reportCancelled(ctx, stderr, stage)
	}
	reportError(stderr, err)
	return 1
}

const userCredentialsHint = "hint: these Application Default Credentials (for example gcloud user credentials from\n" +
	"'gcloud auth application-default login') cannot mint ID tokens. Pass\n" +
	"--impersonate-service-account=SERVICE_ACCOUNT_EMAIL to mint the token as a service account\n" +
	"on which you hold roles/iam.serviceAccountOpenIdTokenCreator (or the broader\n" +
	"roles/iam.serviceAccountTokenCreator).\n"

// maxDiagnosticBytes caps what one failure prints. Library errors can embed
// whole HTTP response bodies (up to 1 MiB on the impersonation path, or a
// proxy's HTML error page).
const maxDiagnosticBytes = 4096

const truncationMarker = " [... truncated]"

// truncateDiagnostic shortens s to at most limit bytes, cutting on a rune
// boundary and ending with truncationMarker when anything was dropped.
func truncateDiagnostic(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := max(limit-len(truncationMarker), 0)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncationMarker
}

func reportError(stderr io.Writer, err error) {
	hint := ""
	if _, ok := errors.AsType[*unsupportedCredentialsError](err); ok {
		hint = userCredentialsHint
	}
	line := truncateDiagnostic(progName+": "+err.Error(), maxDiagnosticBytes-len(hint)-1)
	warnf(stderr, "%s\n%s", line, hint)
}

func reportCancelled(ctx context.Context, stderr io.Writer, stage string) int {
	cause := context.Cause(ctx)
	if te, ok := errors.AsType[*timeoutError](cause); ok {
		warnf(stderr, "%s: %v while %s (see --timeout)\n", progName, te, stage)
	} else {
		warnf(stderr, "%s: interrupted (%v) while %s\n", progName, cause, stage)
	}
	return 1
}
