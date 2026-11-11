package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// googleTokens mints Google OIDC ID tokens.
type googleTokens struct {
	// opts are appended to the client options of the impersonation call.
	// Production passes none; tests inject an HTTP client.
	opts []option.ClientOption
}

// unsupportedCredentialsError marks a failure caused by Application Default
// Credentials of a type that cannot mint ID tokens (typically gcloud user
// credentials). It only drives an extra hint, so detecting it by the
// library's error text is acceptable: a wording change loses the hint, not
// the error.
type unsupportedCredentialsError struct{ err error }

func (e *unsupportedCredentialsError) Error() string { return e.err.Error() }
func (e *unsupportedCredentialsError) Unwrap() error { return e.err }

// unsupportedCredentialsText is what both google.golang.org/api/idtoken and
// cloud.google.com/go/auth/credentials/idtoken report for such credentials.
const unsupportedCredentialsText = "idtoken: unsupported credentials type" //nolint:gosec // G101: an error-message fragment, not a credential

func classifyDefaultCredentialsError(err error) error {
	if strings.Contains(err.Error(), unsupportedCredentialsText) {
		return &unsupportedCredentialsError{err: err}
	}
	return err
}

// defaultIDToken uses Application Default Credentials, falling back to the
// GCE metadata server. The metadata path does not honor ctx (idtoken calls
// metadata.Get without one); run bounds it instead.
func (g googleTokens) defaultIDToken(ctx context.Context, audience string) (string, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		return "", classifyDefaultCredentialsError(err)
	}
	tok, err := ts.Token()
	if err != nil {
		return "", classifyDefaultCredentialsError(err)
	}
	return tok.AccessToken, nil
}

// impersonatedIDToken asks the IAM Credentials API to mint an ID token for
// targetPrincipal, authenticating with Application Default Credentials.
func (g googleTokens) impersonatedIDToken(ctx context.Context, targetPrincipal, audience string) (string, error) {
	ts, err := impersonate.IDTokenSource(ctx, impersonate.IDTokenConfig{
		TargetPrincipal: targetPrincipal,
		Audience:        audience,
		IncludeEmail:    true,
	}, g.opts...)
	if err != nil {
		return "", fmt.Errorf("impersonating %s: %w", targetPrincipal, err)
	}
	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("impersonating %s: %w", targetPrincipal, err)
	}
	if tok.AccessToken == "" {
		return "", errors.New("impersonation returned an empty ID token")
	}
	return tok.AccessToken, nil
}
