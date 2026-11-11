package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/endpoints/private/rulesfn"
	"github.com/aws/smithy-go/logging"
)

// stsAgainst returns an assumer whose STS endpoint is the fake server, set
// through AWS_ENDPOINT_URL_STS exactly as a user would.
func stsAgainst(t *testing.T, srv *fakeSTS) stsAssumer {
	t.Helper()
	isolateEnv(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", srv.URL)
	return stsAssumer{}
}

func stsInput(role string) assumeRoleInput {
	return assumeRoleInput{
		roleARN:          "arn:aws:iam::123456789012:role/" + role,
		roleSessionName:  "sess-1",
		webIdentityToken: testToken,
	}
}

func TestAssumeRoleRequestAndResponse(t *testing.T) {
	srv := newFakeSTS(t)
	a := stsAgainst(t, srv)
	// Static keys in the environment must not lead to a signed request.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA-fake-environment-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "environment-secret")
	t.Setenv("AWS_SESSION_TOKEN", "environment-session")

	out, err := a.assumeRole(t.Context(), stsInput("ok"))
	if err != nil {
		t.Fatal(err)
	}
	reqs := srv.recorded()
	if len(reqs) != 1 {
		t.Fatalf("%d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost {
		t.Errorf("method %s", r.method)
	}
	want := map[string]string{
		"Action":           "AssumeRoleWithWebIdentity",
		"Version":          "2011-06-15",
		"RoleArn":          "arn:aws:iam::123456789012:role/ok",
		"RoleSessionName":  "sess-1",
		"WebIdentityToken": testToken,
	}
	for k, v := range want {
		if got := r.form[k]; len(got) != 1 || got[0] != v {
			t.Errorf("form %s = %v, want %q", k, got, v)
		}
	}
	if _, ok := r.form["DurationSeconds"]; ok {
		t.Error("DurationSeconds sent although not requested")
	}
	for _, h := range []string{"Authorization", "X-Amz-Security-Token", "X-Amz-Date"} {
		if v := r.header.Get(h); v != "" {
			t.Errorf("request is signed: %s: %s", h, v)
		}
	}
	wantOut := credentialProcessOutput{
		Version: 1, AccessKeyID: fakeAccessKeyID, SecretAccessKey: fakeSecretAccessKey,
		SessionToken: fakeSessionToken, Expiration: time.Date(2030, 1, 2, 4, 4, 5, 0, time.UTC),
	}
	if !out.Expiration.Equal(wantOut.Expiration) {
		t.Errorf("expiration %s, want %s", out.Expiration, wantOut.Expiration)
	}
	out.Expiration = wantOut.Expiration
	if out != wantOut {
		t.Errorf("got %+v, want %+v", out, wantOut)
	}
}

func TestAssumeRoleDurationSeconds(t *testing.T) {
	for _, tc := range []struct {
		duration int32
		want     []string
	}{
		{0, nil},
		{900, []string{"900"}},
		{7200, []string{"7200"}},
		{43200, []string{"43200"}},
	} {
		srv := newFakeSTS(t)
		a := stsAgainst(t, srv)
		in := stsInput("ok")
		in.durationSeconds = tc.duration
		out, err := a.assumeRole(t.Context(), in)
		if err != nil {
			t.Fatal(err)
		}
		got := srv.recorded()[0].form["DurationSeconds"]
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("duration %d: sent DurationSeconds=%v, want %v", tc.duration, got, tc.want)
		}
		effective := int(tc.duration)
		if effective == 0 {
			effective = 3600
		}
		base := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
		if d := out.Expiration.Sub(base); d != time.Duration(effective)*time.Second {
			t.Errorf("duration %d: expiration offset %s", tc.duration, d)
		}
	}
}

func TestAssumeRoleServiceError(t *testing.T) {
	srv := newFakeSTS(t)
	a := stsAgainst(t, srv)
	_, err := a.assumeRole(t.Context(), stsInput("deny"))
	if err == nil {
		t.Fatal("no error for AccessDenied")
	}
	want := "AccessDenied: Not authorized to perform sts:AssumeRoleWithWebIdentity (request ID " + fakeRequestID + ")"
	if err.Error() != want {
		t.Errorf("error %q, want %q", err, want)
	}
	if _, ok := errors.AsType[smithy.APIError](err); !ok {
		t.Error("service error is not unwrappable to the SDK API error")
	}
	if strings.Contains(err.Error(), testToken) {
		t.Error("error leaks the ID token")
	}
}

func TestAssumeRoleNoCredentialsResponse(t *testing.T) {
	srv := newFakeSTS(t)
	a := stsAgainst(t, srv)
	_, err := a.assumeRole(t.Context(), stsInput("nocreds"))
	if err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Errorf("error %v, want a no-credentials error", err)
	}
}

func TestAssumeRoleMalformedResponse(t *testing.T) {
	srv := newFakeSTS(t)
	a := stsAgainst(t, srv)
	if _, err := a.assumeRole(t.Context(), stsInput("garbage")); err == nil {
		t.Error("no error for an unparsable response")
	}
}

func TestAssumeRoleConfigError(t *testing.T) {
	isolateEnv(t)
	t.Setenv("AWS_PROFILE", "does-not-exist")
	_, err := stsAssumer{}.assumeRole(t.Context(), stsInput("ok"))
	if _, ok := errors.AsType[*awsConfigError](err); !ok || !strings.HasPrefix(err.Error(), "loading AWS configuration: ") {
		t.Errorf("error %v (%T), want an awsConfigError", err, err)
	}
}

func TestCredentialsFromResponse(t *testing.T) {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	full := func() *types.Credentials {
		return &types.Credentials{
			AccessKeyId: aws.String("A"), SecretAccessKey: aws.String("S"),
			SessionToken: aws.String("T"), Expiration: aws.Time(exp),
		}
	}
	if out, err := credentialsFromResponse(full()); err != nil ||
		out != (credentialProcessOutput{Version: 1, AccessKeyID: "A", SecretAccessKey: "S", SessionToken: "T", Expiration: exp}) {
		t.Errorf("complete credentials: %+v, %v", out, err)
	}
	cases := map[string]*types.Credentials{"credentials": nil}
	for _, field := range []string{"AccessKeyId", "SecretAccessKey", "SessionToken", "Expiration"} {
		c := full()
		switch field {
		case "AccessKeyId":
			c.AccessKeyId = nil
		case "SecretAccessKey":
			c.SecretAccessKey = aws.String("")
		case "SessionToken":
			c.SessionToken = nil
		case "Expiration":
			c.Expiration = nil
		}
		cases[field] = c
	}
	for field, c := range cases {
		_, err := credentialsFromResponse(c)
		if err == nil || !strings.Contains(err.Error(), strings.TrimSuffix(field, "credentials")) {
			t.Errorf("missing %s: error %v", field, err)
		}
	}
}

// TestRegionPrecedence observes the endpoint the SDK actually calls, so it
// pins both the resolution order and that the resolved region is used.
func TestRegionPrecedence(t *testing.T) {
	const profileConfig = "[default]\nregion = sa-east-1\n\n[profile p]\nregion = eu-central-1\n"
	tests := []struct {
		name       string
		flag       string
		env        map[string]string
		withConfig bool
		want       string
	}{
		{"fallback", "", nil, false, "us-east-1"},
		{"default profile", "", nil, true, "sa-east-1"},
		{"named profile", "", map[string]string{"AWS_PROFILE": "p"}, true, "eu-central-1"},
		{"AWS_DEFAULT_REGION over profile", "", map[string]string{"AWS_PROFILE": "p", "AWS_DEFAULT_REGION": "ca-central-1"}, true, "ca-central-1"},
		{"AWS_REGION over AWS_DEFAULT_REGION", "", map[string]string{"AWS_PROFILE": "p", "AWS_DEFAULT_REGION": "ca-central-1", "AWS_REGION": "eu-west-1"}, true, "eu-west-1"},
		{"flag over everything", "ap-southeast-2", map[string]string{"AWS_PROFILE": "p", "AWS_DEFAULT_REGION": "ca-central-1", "AWS_REGION": "eu-west-1"}, true, "ap-southeast-2"},
		{"flag alone", "ap-south-1", nil, false, "ap-south-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			home := isolateEnv(t)
			if tc.withConfig {
				writeFile(t, filepath.Join(home, "aws-config"), profileConfig, 0o600)
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			rt := &recordingTransport{}
			a := stsAssumer{configOptions: []func(*config.LoadOptions) error{
				config.WithHTTPClient(&http.Client{Transport: rt}),
			}}
			in := stsInput("ok")
			in.region = tc.flag
			if _, err := a.assumeRole(t.Context(), in); err != nil {
				t.Fatal(err)
			}
			reqs := rt.recorded()
			if len(reqs) != 1 {
				t.Fatalf("%d requests, want exactly 1 (no retry)", len(reqs))
			}
			if want := "sts." + tc.want + ".amazonaws.com"; reqs[0].host != want {
				t.Errorf("endpoint host %q, want %q", reqs[0].host, want)
			}
		})
	}
}

// TestNoAWSCredentialResolution: the SDK is configured with anonymous
// credentials, so a profile's credential_process (possibly this very program)
// is never run, even if something asked the config for credentials. The
// operation is unsigned anyway; this pins the defense in depth.
func TestNoAWSCredentialResolution(t *testing.T) {
	home := isolateEnv(t)
	marker := filepath.Join(home, "credential-process-ran")
	script := filepath.Join(home, "cp.sh")
	writeFile(t, script, "#!/bin/sh\ntouch '"+marker+"'\necho '{\"Version\":1,\"AccessKeyId\":\"A\",\"SecretAccessKey\":\"S\"}'\n", 0o700)
	writeFile(t, filepath.Join(home, "aws-config"),
		"[profile selfref]\nregion = eu-central-1\ncredential_process = "+script+"\n", 0o600)
	t.Setenv("AWS_PROFILE", "selfref")

	rt := &recordingTransport{}
	a := stsAssumer{configOptions: []func(*config.LoadOptions) error{
		config.WithHTTPClient(&http.Client{Transport: rt}),
	}}
	cfg, err := a.loadConfig(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !aws.IsCredentialsProvider(cfg.Credentials, aws.AnonymousCredentials{}) {
		t.Errorf("credentials provider is %T, want aws.AnonymousCredentials", cfg.Credentials)
	}
	if _, err := cfg.Credentials.Retrieve(t.Context()); err == nil {
		t.Error("credentials were retrieved; want anonymous (no credentials)")
	}
	if _, err := a.assumeRole(t.Context(), stsInput("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("the profile's credential_process was invoked")
	}
	if reqs := rt.recorded(); len(reqs) != 1 || reqs[0].header.Get("Authorization") != "" {
		t.Errorf("unexpected requests or signed request: %+v", reqs)
	}
}

// TestValidRegionMatchesSDK checks --region validation against the very
// function the STS client uses to bind the region (service/sts endpoints.go
// bindRegion), so a real region is never rejected and nothing the SDK would
// refuse gets through to after the token fetch.
func TestValidRegionMatchesSDK(t *testing.T) {
	for _, r := range []string{
		"us-east-1", "eu-west-1", "us-gov-west-1", "cn-north-1", "us-iso-east-1", "fips-us-east-1",
		"us-east-1-fips", "aws-global", "EU-WEST-1", "a", strings.Repeat("a", 63), strings.Repeat("a", 64),
		"eu.west", "eu..west", ".eu", "eu.", "-eu", "eu-", "eu.-west", "eu west 1", "eu_west_1",
		"eu/west", "é", "eu-west-1\n", "1",
	} {
		if got, want := validRegion(r), rulesfn.IsValidHostLabel(r, true); got != want {
			t.Errorf("validRegion(%q) = %v, SDK says %v", r, got, want)
		}
	}
}

func TestSDKLoggerDiscards(t *testing.T) {
	isolateEnv(t)
	cfg, err := stsAssumer{}.loadConfig(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Logger.(logging.Nop); !ok {
		t.Errorf("SDK logger is %T; anything else may write to stderr", cfg.Logger)
	}
}
