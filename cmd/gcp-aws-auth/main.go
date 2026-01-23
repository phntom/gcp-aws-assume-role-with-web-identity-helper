package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/impersonate"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// CredentialProcessOutput matches the format expected by AWS credential_process
type CredentialProcessOutput struct {
	Version         int       `json:"Version"`
	AccessKeyId     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
}

func main() {
	// Ensure logs go to stderr to avoid interfering with JSON output on stdout
	log.SetOutput(os.Stderr)
	log.SetFlags(0)

	var (
		roleArn         string
		roleSessionName string
		impersonateSA   string
	)

	flag.StringVar(&roleArn, "role-arn", "", "The ARN of the AWS IAM Role to assume")
	flag.StringVar(&roleSessionName, "role-session-name", "", "The session name for the assumed role")
	flag.StringVar(&impersonateSA, "impersonate-service-account", "", "Optional: The GCP Service Account email to impersonate")
	flag.Parse()

	if roleArn == "" || roleSessionName == "" {
		log.Fatal("Error: --role-arn and --role-session-name are required.")
	}

	ctx := context.Background()
	audience := "sts.amazonaws.com"

	// Step 1: Get GCP ID Token
	var token string
	var err error

	if impersonateSA != "" {
		token, err = getImpersonatedIDToken(ctx, impersonateSA, audience)
	} else {
		token, err = getDefaultIDToken(ctx, audience)
	}

	if err != nil {
		log.Fatalf("Failed to get GCP ID token: %v", err)
	}

	// Step 2: Assume Role with Web Identity
	creds, err := assumeRole(ctx, token, roleArn, roleSessionName)
	if err != nil {
		log.Fatalf("Failed to assume role: %v", err)
	}

	// Step 3: Output JSON
	output := CredentialProcessOutput{
		Version:         1,
		AccessKeyId:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
		Expiration:      *creds.Expiration,
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ") // Pretty print for readability, though not strictly required
	if err := encoder.Encode(output); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
}

func getDefaultIDToken(ctx context.Context, audience string) (string, error) {
	ts, err := idtoken.NewTokenSource(ctx, audience)
	if err != nil {
		return "", fmt.Errorf("idtoken.NewTokenSource: %w", err)
	}

	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}
	return tok.AccessToken, nil
}

func getImpersonatedIDToken(ctx context.Context, targetPrincipal string, audience string) (string, error) {
	ts, err := impersonate.IDTokenSource(ctx, impersonate.IDTokenConfig{
		TargetPrincipal: targetPrincipal,
		Audience:        audience,
		IncludeEmail:    true,
	})
	if err != nil {
		return "", fmt.Errorf("impersonate.IDTokenSource: %w", err)
	}

	tok, err := ts.Token()
	if err != nil {
		return "", fmt.Errorf("failed to fetch impersonated token: %w", err)
	}
	return tok.AccessToken, nil
}

func assumeRole(ctx context.Context, idToken, roleArn, roleSessionName string) (*types.Credentials, error) {
	// Load default config to get region and other defaults.
	// We don't need credentials in the config since we are using WebIdentity.
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load aws config: %w", err)
	}

	stsClient := sts.NewFromConfig(cfg)

	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleArn),
		RoleSessionName:  aws.String(roleSessionName),
		WebIdentityToken: aws.String(idToken),
	}

	resp, err := stsClient.AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		if strings.Contains(err.Error(), "Invalid Configuration: Missing Region") {
			cfg.Region = "us-east-1"
			stsClient = sts.NewFromConfig(cfg)
			resp, err = stsClient.AssumeRoleWithWebIdentity(ctx, input)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", err)
	}

	return resp.Credentials, nil
}
