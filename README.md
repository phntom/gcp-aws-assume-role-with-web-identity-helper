# GCP to AWS Credential Process

This tool is a standalone Go executable designed to be used as an AWS `credential_process`. It authenticates with Google Cloud Platform (GCP), obtains an OpenID Connect (OIDC) ID token, and exchanges it for temporary AWS credentials using the `AssumeRoleWithWebIdentity` API.

## Usage

This tool is intended to be configured in your `~/.aws/config` file.

### Arguments

*   `--role-arn` (Required): The ARN of the AWS IAM Role to assume.
*   `--role-session-name` (Required): An identifier for the assumed role session.
*   `--impersonate-service-account` (Optional): The email address of a GCP Service Account to impersonate. If not provided, the tool uses the environment's default GCP credentials.

### Configuration Example

Add the following to your `~/.aws/config`:

```ini
[profile my-gcp-profile]
credential_process = /path/to/gcp-aws-auth --role-arn arn:aws:iam::123456789012:role/my-role --role-session-name my-session --impersonate-service-account my-sa@my-project.iam.gserviceaccount.com
```

## References

For additional details on the underlying mechanism, see:
https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/
