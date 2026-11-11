package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/api/option"
)

// Note: metadata.OnGCE caches its answer for the life of the process. Every
// test here sets GCE_METADATA_HOST (isolateEnv does), which makes OnGCE answer
// true without probing, so the cached answer is the same whichever test runs
// first and no test ever probes the real metadata address.

func TestDefaultIDTokenFromMetadataServer(t *testing.T) {
	isolateEnv(t)
	md := newFakeMetadata(t)
	t.Setenv("GCE_METADATA_HOST", md.host())

	tok, err := googleTokens{}.defaultIDToken(t.Context(), "my-audience")
	if err != nil {
		t.Fatal(err)
	}
	if tok != fakeJWT("my-audience") {
		t.Errorf("token %q", tok)
	}
	var identity []metadataRequest
	for _, r := range md.recorded() {
		if strings.HasSuffix(r.path, "/identity") {
			identity = append(identity, r)
		}
	}
	if len(identity) != 1 {
		t.Fatalf("%d identity requests, want 1: %+v", len(identity), md.recorded())
	}
	r := identity[0]
	if r.query.Get("audience") != "my-audience" || r.query.Get("format") != "full" || r.flavor != "Google" {
		t.Errorf("identity request %+v", r)
	}
}

func TestDefaultIDTokenMetadataError(t *testing.T) {
	isolateEnv(t)
	// A server that rejects everything: the error must surface, not a token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Metadata-Flavor", "Google")
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("GCE_METADATA_HOST", strings.TrimPrefix(srv.URL, "http://"))
	if _, err := (googleTokens{}).defaultIDToken(t.Context(), "aud"); err == nil {
		t.Error("no error from a failing metadata server")
	}
}

// TestUserCredentialsAreRecognized pins the library error text that the
// --impersonate-service-account hint for gcloud user credentials depends on,
// for both the legacy and the new Google auth library code paths. If an
// upstream wording change breaks the match, this test fails.
func TestUserCredentialsAreRecognized(t *testing.T) {
	for _, newAuth := range []string{"", "true"} {
		t.Run("new_auth_lib="+newAuth, func(t *testing.T) {
			home := isolateEnv(t)
			if newAuth != "" {
				t.Setenv("GOOGLE_API_GO_EXPERIMENTAL_ENABLE_NEW_AUTH_LIB", newAuth)
			}
			adc := filepath.Join(home, "adc.json")
			writeFile(t, adc, `{"type":"authorized_user","client_id":"id.apps.googleusercontent.com",
				"client_secret":"adc-client-secret","refresh_token":"adc-refresh-token"}`, 0o600)
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", adc)

			_, err := googleTokens{}.defaultIDToken(t.Context(), "aud")
			if _, ok := errors.AsType[*unsupportedCredentialsError](err); !ok {
				t.Fatalf("error %v (%T) not recognized as unsupported credentials", err, err)
			}
			for _, secret := range []string{"adc-client-secret", "adc-refresh-token"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks %s", secret)
				}
			}
		})
	}
}

func TestClassifyDefaultCredentialsError(t *testing.T) {
	plain := errors.New("idtoken: couldn't find any credentials")
	if got := classifyDefaultCredentialsError(plain); got.Error() != plain.Error() || isUnsupported(got) {
		t.Errorf("unrelated error reclassified: %v", got)
	}
	inner := fmt.Errorf("wrapped: %w", errors.New(`idtoken: unsupported credentials type: "x"`))
	got := classifyDefaultCredentialsError(inner)
	if !isUnsupported(got) || !errors.Is(got, inner) || got.Error() != inner.Error() {
		t.Errorf("got %v", got)
	}
}

func isUnsupported(err error) bool {
	_, ok := errors.AsType[*unsupportedCredentialsError](err)
	return ok
}

// redirectTransport sends requests for the IAM Credentials API to a test
// server and refuses every other host, so nothing can reach Google.
type redirectTransport struct{ target *url.URL }

func (rt redirectTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != "iamcredentials.googleapis.com" {
		return nil, fmt.Errorf("test transport: refusing request to %s", r.URL.Host)
	}
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = rt.target.Scheme, rt.target.Host
	r.Host = rt.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

type generateIDTokenCall struct {
	method, path string
	body         map[string]any
}

func newFakeIAM(t *testing.T, status int, response string) (googleTokens, *[]generateIDTokenCall, *sync.Mutex) {
	t.Helper()
	var (
		mu    sync.Mutex
		calls []generateIDTokenCall
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		mu.Lock()
		calls = append(calls, generateIDTokenCall{r.Method, r.URL.Path, body})
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: redirectTransport{target: target}}
	return googleTokens{opts: []option.ClientOption{option.WithHTTPClient(client)}}, &calls, &mu
}

func TestImpersonatedIDToken(t *testing.T) {
	isolateEnv(t)
	jwt := fakeJWT("custom-aud")
	g, calls, mu := newFakeIAM(t, http.StatusOK, `{"token":"`+jwt+`"}`)

	tok, err := g.impersonatedIDToken(t.Context(), "deployer@proj.iam.gserviceaccount.com", "custom-aud")
	if err != nil {
		t.Fatal(err)
	}
	if tok != jwt {
		t.Errorf("token %q", tok)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*calls) != 1 {
		t.Fatalf("%d calls, want 1", len(*calls))
	}
	c := (*calls)[0]
	if c.method != http.MethodPost || c.path != "/v1/projects/-/serviceAccounts/deployer@proj.iam.gserviceaccount.com:generateIdToken" {
		t.Errorf("request %s %s", c.method, c.path)
	}
	if c.body["audience"] != "custom-aud" || c.body["includeEmail"] != true {
		t.Errorf("request body %v, want audience custom-aud and includeEmail true", c.body)
	}
}

// TestRunImpersonationAudienceReachesIAM drives run with the real
// impersonation code, proving the --audience value (and the principal) reach
// the generateIdToken request, with includeEmail set.
func TestRunImpersonationAudienceReachesIAM(t *testing.T) {
	isolateEnv(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "sts.amazonaws.com"}, // contract default, pinned as a literal
		{[]string{"--audience", "custom-aud"}, "custom-aud"},
	} {
		g, calls, mu := newFakeIAM(t, http.StatusOK, `{"token":"`+fakeJWT(tc.want)+`"}`)
		f := newFakeDeps()
		d := f.deps()
		d.impersonatedIDToken = g.impersonatedIDToken
		args := append(baseArgs("--impersonate-service-account", "deployer@proj.iam.gserviceaccount.com"), tc.args...)
		var out, errb bytes.Buffer
		if code := run(t.Context(), args, &out, &errb, d); code != 0 {
			t.Fatalf("%v: exit %d, stderr %q", tc.args, code, errb.String())
		}
		mu.Lock()
		if len(*calls) != 1 {
			t.Fatalf("%v: %d generateIdToken calls", tc.args, len(*calls))
		}
		c := (*calls)[0]
		mu.Unlock()
		if c.path != "/v1/projects/-/serviceAccounts/deployer@proj.iam.gserviceaccount.com:generateIdToken" ||
			c.body["audience"] != tc.want || c.body["includeEmail"] != true {
			t.Errorf("%v: request %s %v, want audience %q", tc.args, c.path, c.body, tc.want)
		}
		if got := f.assumeInputs[0].webIdentityToken; got != fakeJWT(tc.want) {
			t.Errorf("%v: STS got token %q", tc.args, got)
		}
	}
}

func TestImpersonatedIDTokenErrors(t *testing.T) {
	isolateEnv(t)
	t.Run("permission denied", func(t *testing.T) {
		g, _, _ := newFakeIAM(t, http.StatusForbidden, `{"error":{"code":403,"message":"Permission 'iam.serviceAccounts.getOpenIdToken' denied"}}`)
		_, err := g.impersonatedIDToken(t.Context(), "sa@p.iam.gserviceaccount.com", "aud")
		if err == nil || !strings.Contains(err.Error(), "impersonating sa@p.iam.gserviceaccount.com") || !strings.Contains(err.Error(), "403") {
			t.Errorf("error %v", err)
		}
	})
	t.Run("empty token", func(t *testing.T) {
		g, _, _ := newFakeIAM(t, http.StatusOK, `{"token":""}`)
		if _, err := g.impersonatedIDToken(t.Context(), "sa@p.iam.gserviceaccount.com", "aud"); err == nil {
			t.Error("empty token accepted")
		}
	})
	t.Run("missing principal", func(t *testing.T) {
		g, _, _ := newFakeIAM(t, http.StatusOK, `{}`)
		if _, err := g.impersonatedIDToken(t.Context(), "", "aud"); err == nil {
			t.Error("empty principal accepted")
		}
	})
}
