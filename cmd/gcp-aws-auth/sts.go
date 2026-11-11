package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/aws/smithy-go"
	"github.com/aws/smithy-go/logging"
)

// fallbackRegion is used when neither --region nor the SDK's own resolution
// (environment, shared config profile) yields a region.
const fallbackRegion = "us-east-1"

// stsAssumer calls STS AssumeRoleWithWebIdentity with the real AWS SDK.
type stsAssumer struct {
	// configOptions are appended to the config.LoadDefaultConfig options.
	// Production passes none; tests inject an HTTP client.
	configOptions []func(*config.LoadOptions) error
}

// awsConfigError reports that the AWS configuration (environment, shared
// config files, profile) could not be loaded; STS was not called.
type awsConfigError struct{ err error }

func (e *awsConfigError) Error() string { return "loading AWS configuration: " + e.err.Error() }
func (e *awsConfigError) Unwrap() error { return e.err }

// loadConfig loads the SDK's default configuration (environment and shared
// config, so endpoint overrides, CA bundles, proxies, FIPS and profiles keep
// working) with three fixed adjustments:
//   - Credentials are anonymous. AssumeRoleWithWebIdentity is an unsigned
//     operation in the SDK, so no credentials would be resolved for it anyway;
//     this is defense in depth that keeps the SDK from ever looking for AWS
//     credentials, which could otherwise lead back into this very
//     credential_process.
//   - The SDK logger discards. It defaults to stderr, and middleware warnings
//     (for example about an unparsable Date header) would break the promise
//     of an empty stderr on success. Failures are reported as errors anyway.
//   - The region is resolved up front, with us-east-1 as the last resort.
func (a stsAssumer) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
		config.WithLogger(logging.Nop{}),
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	opts = append(opts, a.configOptions...)
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, &awsConfigError{err: err}
	}
	if cfg.Region == "" {
		cfg.Region = fallbackRegion
	}
	return cfg, nil
}

func (a stsAssumer) assumeRole(ctx context.Context, in assumeRoleInput) (credentialProcessOutput, error) {
	cfg, err := a.loadConfig(ctx, in.region)
	if err != nil {
		return credentialProcessOutput{}, err
	}
	input := &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(in.roleARN),
		RoleSessionName:  aws.String(in.roleSessionName),
		WebIdentityToken: aws.String(in.webIdentityToken),
	}
	if in.durationSeconds != 0 {
		input.DurationSeconds = aws.Int32(in.durationSeconds)
	}
	resp, err := sts.NewFromConfig(cfg).AssumeRoleWithWebIdentity(ctx, input)
	if err != nil {
		return credentialProcessOutput{}, describeSTSError(err)
	}
	return credentialsFromResponse(resp.Credentials)
}

// describeSTSError shortens service errors to "Code: message (request ID x)".
// Other errors (network, configuration) are returned unchanged.
func describeSTSError(err error) error {
	apiErr, ok := errors.AsType[smithy.APIError](err)
	if !ok {
		return err
	}
	msg := apiErr.ErrorCode()
	if m := apiErr.ErrorMessage(); m != "" {
		msg += ": " + m
	}
	if re, ok := errors.AsType[*awshttp.ResponseError](err); ok && re.ServiceRequestID() != "" {
		msg += " (request ID " + re.ServiceRequestID() + ")"
	}
	return &stsServiceError{msg: msg, err: err}
}

type stsServiceError struct {
	msg string
	err error
}

func (e *stsServiceError) Error() string { return e.msg }
func (e *stsServiceError) Unwrap() error { return e.err }

// credentialsFromResponse converts STS credentials, refusing incomplete ones.
func credentialsFromResponse(c *types.Credentials) (credentialProcessOutput, error) {
	if c == nil {
		return credentialProcessOutput{}, errors.New("STS response contains no credentials")
	}
	var missing []string
	if aws.ToString(c.AccessKeyId) == "" {
		missing = append(missing, "AccessKeyId")
	}
	if aws.ToString(c.SecretAccessKey) == "" {
		missing = append(missing, "SecretAccessKey")
	}
	if aws.ToString(c.SessionToken) == "" {
		missing = append(missing, "SessionToken")
	}
	if c.Expiration == nil {
		missing = append(missing, "Expiration")
	}
	if len(missing) > 0 {
		return credentialProcessOutput{}, fmt.Errorf("STS response credentials lack %s", strings.Join(missing, ", "))
	}
	return credentialProcessOutput{
		Version:         1,
		AccessKeyID:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
		Expiration:      *c.Expiration,
	}, nil
}
