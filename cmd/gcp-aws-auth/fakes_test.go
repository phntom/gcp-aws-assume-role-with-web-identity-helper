package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Values the fake STS hands out; tests assert they never reach stderr.
const (
	fakeAccessKeyID     = "ASIA-fake-access-key-id"
	fakeSecretAccessKey = "fakeSecretAccessKey/DoNotUse+0000000000"
	fakeSessionToken    = "FakeSessionTokenAAAAABBBBBCCCCC=="
	fakeRequestID       = "fake-request-id-0001"
)

// isolateEnv removes every variable that the AWS SDK or the Google libraries
// read from the environment, so tests behave the same on a developer machine,
// in CI and under a hostile outer environment. HOME and the shared-config
// paths point into an empty temporary directory. It returns that directory.
func isolateEnv(t *testing.T) string {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		for _, prefix := range []string{"AWS_", "GOOGLE_", "GCE_", "CLOUDSDK_"} {
			if strings.HasPrefix(k, prefix) {
				unsetenv(t, k)
			}
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLOUDSDK_CONFIG", filepath.Join(home, "gcloud"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(home, "aws-config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(home, "aws-credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	// Nothing may reach a real metadata server: a dead loopback port.
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
	return home
}

// unsetenv unsets k for the duration of the test (t.Setenv restores it).
func unsetenv(t *testing.T, k string) {
	t.Helper()
	t.Setenv(k, "")
	if err := os.Unsetenv(k); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// fakeJWT builds an unsigned JWT-shaped token carrying the audience.
func fakeJWT(audience string) string {
	enc := base64.RawURLEncoding.EncodeToString
	payload, _ := json.Marshal(map[string]any{"aud": audience, "iss": "https://accounts.google.com"})
	return enc([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc(payload) + ".c2lnbmF0dXJl"
}

// ---------------------------------------------------------------- metadata

type metadataRequest struct {
	path   string
	query  url.Values
	flavor string
}

type fakeMetadata struct {
	*httptest.Server
	mu       sync.Mutex
	requests []metadataRequest
}

// newFakeMetadata serves the GCE metadata endpoints idtoken uses. The
// identity endpoint hangs (until the client goes away) for audience "hang".
func newFakeMetadata(t *testing.T) *fakeMetadata {
	t.Helper()
	release := make(chan struct{})
	f := &fakeMetadata{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, metadataRequest{r.URL.Path, r.URL.Query(), r.Header.Get("Metadata-Flavor")})
		f.mu.Unlock()
		w.Header().Set("Metadata-Flavor", "Google")
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "missing Metadata-Flavor", http.StatusForbidden)
			return
		}
		switch strings.TrimSuffix(r.URL.Path, "/") {
		case "/computeMetadata/v1/instance/service-accounts/default/identity":
			aud := r.URL.Query().Get("audience")
			if aud == "hang" {
				select {
				case <-r.Context().Done():
				case <-release:
				}
				return
			}
			_, _ = io.WriteString(w, fakeJWT(aud))
		case "/computeMetadata/v1/project/project-id":
			_, _ = io.WriteString(w, "fake-project")
		case "/computeMetadata/v1/instance/service-accounts/default/email":
			_, _ = io.WriteString(w, "fake-sa@fake-project.iam.gserviceaccount.com")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.Close)
	t.Cleanup(func() { close(release) }) // runs before Close (LIFO)
	return f
}

func (f *fakeMetadata) host() string { return strings.TrimPrefix(f.URL, "http://") }

func (f *fakeMetadata) recorded() []metadataRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]metadataRequest(nil), f.requests...)
}

// --------------------------------------------------------------------- STS

type stsRequest struct {
	host   string
	method string
	header http.Header
	form   url.Values
}

// stsResponder answers one recorded STS request the way the real service
// would, keyed on the RoleArn: role/deny -> AccessDenied, role/nocreds -> 200
// without credentials, role/garbage -> unparsable 200, role/slow -> block
// (fakeSTS only), role/baddate -> success with a malformed Date header.
func stsRespond(form url.Values) (status int, body string) {
	role := form.Get("RoleArn")
	switch {
	case strings.Contains(role, "role/deny"):
		return http.StatusForbidden, `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error><Type>Sender</Type><Code>AccessDenied</Code>
  <Message>Not authorized to perform sts:AssumeRoleWithWebIdentity</Message></Error>
  <RequestId>` + fakeRequestID + `</RequestId>
</ErrorResponse>`
	case strings.Contains(role, "role/garbage"):
		return http.StatusOK, "this is not XML"
	}
	creds := ""
	if !strings.Contains(role, "role/nocreds") {
		duration := 3600
		if d := form.Get("DurationSeconds"); d != "" {
			_, _ = fmt.Sscan(d, &duration)
		}
		exp := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC).Add(time.Duration(duration) * time.Second)
		creds = `<Credentials>
      <AccessKeyId>` + fakeAccessKeyID + `</AccessKeyId>
      <SecretAccessKey>` + fakeSecretAccessKey + `</SecretAccessKey>
      <SessionToken>` + fakeSessionToken + `</SessionToken>
      <Expiration>` + exp.Format(time.RFC3339) + `</Expiration>
    </Credentials>`
	}
	return http.StatusOK, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <AssumedRoleUser><Arn>arn:aws:sts::123456789012:assumed-role/r/s</Arn><AssumedRoleId>AROA:s</AssumedRoleId></AssumedRoleUser>
    ` + creds + `
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata><RequestId>` + fakeRequestID + `</RequestId></ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`
}

func readSTSRequest(r *http.Request) stsRequest {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	return stsRequest{host: r.URL.Host, method: r.Method, header: r.Header.Clone(), form: form}
}

type fakeSTS struct {
	*httptest.Server
	mu       sync.Mutex
	requests []stsRequest
	arrived  chan struct{} // receives once per request, never blocks
}

func newFakeSTS(t *testing.T) *fakeSTS {
	t.Helper()
	release := make(chan struct{})
	f := &fakeSTS{arrived: make(chan struct{}, 100)}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := readSTSRequest(r)
		req.host = r.Host
		f.mu.Lock()
		f.requests = append(f.requests, req)
		f.mu.Unlock()
		select {
		case f.arrived <- struct{}{}:
		default:
		}
		if strings.Contains(req.form.Get("RoleArn"), "role/slow") {
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return
		}
		status, body := stsRespond(req.form)
		if strings.Contains(req.form.Get("RoleArn"), "role/baddate") {
			// A sloppy proxy or custom endpoint; the SDK would log a warning.
			w.Header().Set("Date", "not-a-date")
		}
		w.Header().Set("Content-Type", "text/xml")
		w.Header().Set("X-Amzn-Requestid", fakeRequestID)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.Close)
	t.Cleanup(func() { close(release) })
	return f
}

func (f *fakeSTS) recorded() []stsRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]stsRequest(nil), f.requests...)
}

// recordingTransport answers STS requests in-process without any network,
// so the endpoint the SDK chose (and thus the region) can be observed.
type recordingTransport struct {
	mu       sync.Mutex
	requests []stsRequest
}

func (rt *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	req := readSTSRequest(r)
	_ = r.Body.Close()
	rt.mu.Lock()
	rt.requests = append(rt.requests, req)
	rt.mu.Unlock()
	status, body := stsRespond(req.form)
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"text/xml"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    r,
	}, nil
}

func (rt *recordingTransport) recorded() []stsRequest {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return append([]stsRequest(nil), rt.requests...)
}
