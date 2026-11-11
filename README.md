# gcp-aws-auth

[![CI](https://github.com/phntom/gcp-aws-assume-role-with-web-identity-helper/actions/workflows/ci.yml/badge.svg)](https://github.com/phntom/gcp-aws-assume-role-with-web-identity-helper/actions/workflows/ci.yml)

`gcp-aws-auth` lets workloads that run as a Google Cloud service account use AWS without stored AWS keys. It is an AWS [`credential_process`](https://docs.aws.amazon.com/sdkref/latest/guide/feature-process-credentials.html) helper: the AWS CLI and SDKs run it and read temporary credentials from its stdout.

Each run does two things:

1. Gets a Google OIDC ID token. By default it uses Application Default Credentials (ADC) or the metadata server. With `--impersonate-service-account`, it asks the IAM Service Account Credentials API to mint the token for that service account.
2. Sends the token to AWS STS `AssumeRoleWithWebIdentity`, which needs no AWS credentials, and prints the returned credentials as JSON.

## Quick start

You need a Google service account, an IAM role whose trust policy accepts that service account (see [AWS setup](#aws-setup)), and the binary installed (see [Installation](#installation)).

Add a profile to `~/.aws/config`. Use the full path to the binary; the AWS CLI documentation says not to use `~` or environment variables in `credential_process`.

```ini
[profile gcp]
credential_process = /usr/local/bin/gcp-aws-auth --role-arn arn:aws:iam::123456789012:role/gcp-workload --role-session-name my-workload --region us-east-1
```

On a laptop where ADC are your own gcloud user credentials, add `--impersonate-service-account my-sa@my-project.iam.gserviceaccount.com` to that line (see [Google setup](#google-setup)).

Check that it works:

```sh
aws sts get-caller-identity --profile gcp
```

The `Arn` in the output is `arn:aws:sts::123456789012:assumed-role/gcp-workload/my-workload`.

## Installation

### Release binaries

Each [GitHub release](https://github.com/phntom/gcp-aws-assume-role-with-web-identity-helper/releases) has one binary per platform. Tags have no `v` prefix, for example `0.0.2`.

| Asset | Platform |
| --- | --- |
| `gcp-aws-auth-linux-amd64` | Linux x86-64 |
| `gcp-aws-auth-linux-arm64` | Linux ARM64 |
| `gcp-aws-auth-linux-arm` | Linux ARMv7 |
| `gcp-aws-auth-darwin-amd64` | macOS Intel |
| `gcp-aws-auth-darwin-arm64` | macOS Apple silicon |
| `gcp-aws-auth-windows-amd64.exe` | Windows x86-64 |
| `gcp-aws-auth-windows-386.exe` | Windows x86 |

Releases after `0.0.2` also have `checksums.txt`. `0.0.1` and `0.0.2` do not. To download and verify on Linux (replace `TAG`):

```sh
base=https://github.com/phntom/gcp-aws-assume-role-with-web-identity-helper/releases/download/TAG
curl -fL -O "$base/gcp-aws-auth-linux-amd64" -O "$base/checksums.txt"
sha256sum --ignore-missing -c checksums.txt
sudo install -m 0755 gcp-aws-auth-linux-amd64 /usr/local/bin/gcp-aws-auth
```

Releases built with Go 1.27, which are those after `0.0.2`, require macOS 13 Ventura or later.

### go install

Requires Go 1.27.4 or later. With the default `GOTOOLCHAIN=auto`, Go 1.21 and later download that toolchain for you.

```sh
go install github.com/phntom/gcp-aws-assume-role-with-web-identity-helper/cmd/gcp-aws-auth@latest
```

The binary is named `gcp-aws-auth` and lands in `$(go env GOPATH)/bin`, or `GOBIN` if set. The release tags are not Go semantic-version tags, so `@latest` builds the newest commit on the default branch, and `--version` prints a pseudo-version.

### Container image

`phntom/gcp-aws-assume-role-with-web-identity-helper` on Docker Hub, tags `<release tag>` and `latest`, for `linux/amd64`, `linux/arm64` and `linux/arm` (v7). It is Alpine-based. The binary is `/usr/bin/gcp-aws-auth` and is the entrypoint:

```sh
docker run --rm phntom/gcp-aws-assume-role-with-web-identity-helper:latest --version
```

To add the binary to your own image, pin a release tag (replace `TAG`):

```dockerfile
COPY --from=phntom/gcp-aws-assume-role-with-web-identity-helper:TAG /usr/bin/gcp-aws-auth /usr/local/bin/gcp-aws-auth
```

## Reference

```text
gcp-aws-auth --role-arn ARN --role-session-name NAME [flags]
```

Flags take one or two dashes (`-region` and `--region` are the same). Values go after a space or `=`.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--role-arn` | none, required | ARN of the AWS IAM role to assume. |
| `--role-session-name` | none, required | Session name for the assumed role. STS allows 2 to 64 characters from `[\w+=,.@-]`. |
| `--impersonate-service-account` | empty | Email of a Google service account to impersonate when minting the ID token. Needed when ADC are gcloud user credentials. A blank value is a usage error. |
| `--audience` | `sts.amazonaws.com` | Audience (`aud` claim) of the Google ID token. Must not be empty. |
| `--region` | empty | AWS region for the STS call. A value that is not a valid region name is a usage error. See [Region](#region). |
| `--duration-seconds` | `0` | Session duration in seconds, 900 to 43200 and at most the role's maximum session duration. `0` omits the parameter and STS uses its default of 3600 (one hour). |
| `--timeout` | `1m0s` | Time limit for the whole run, as a duration with a unit such as `30s`, `2m` or `1m30s`. `0` disables it. |
| `--version` | `false` | Print the version and exit. |

`-h` or `--help` prints the same information.

A `--duration-seconds` value above the role's maximum session duration makes STS fail the call. The maximum is set on the role, from 1 to 12 hours, default 1 hour: `aws iam update-role --role-name gcp-workload --max-session-duration 43200`.

### Output and exit codes

On success the tool writes one JSON document to stdout, in the `credential_process` format, and nothing else. `Expiration` is RFC 3339.

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-11-11T13:00:00Z"
}
```

Errors and hints go to stderr, one diagnostic of at most 4 KiB. On success stderr stays empty, and nothing is written to stdout unless every step succeeded.

| Code | Meaning |
| --- | --- |
| `0` | Success, or `--help` / `--version`. |
| `1` | Runtime failure: Google token, STS call, timeout, or interrupt (SIGINT or SIGTERM). |
| `2` | Usage error: unknown flag, bad value, missing required flag, or a positional argument. |

### Region

The STS call uses the first of: `--region`; `AWS_REGION`; `AWS_DEFAULT_REGION`; `region` in the shared config profile named by `AWS_PROFILE`, else `AWS_DEFAULT_PROFILE`, else `default`; `us-east-1`.

The helper sees only its own environment. The AWS CLI v2 starts it as a child process that inherits the CLI's environment, and `aws --profile gcp` selects the profile inside the CLI without setting `AWS_PROFILE`. So a `region` in `[profile gcp]` reaches the helper only when the profile is selected with `AWS_PROFILE=gcp`. With `--profile gcp`, the helper reads `[default]`. To avoid depending on this, put `--region` on the `credential_process` line.

### Timeout

`--timeout` bounds the whole run, both the Google and the STS step. When it expires the tool exits 1 with `timed out after 1m0s while <step> (see --timeout)`. A bare number such as `30` is a usage error; write `30s`.

### Environment

The tool reads no environment variables itself. Its libraries do:

- AWS SDK for Go v2: `AWS_REGION`, `AWS_DEFAULT_REGION`, `AWS_PROFILE`, `AWS_DEFAULT_PROFILE`, `AWS_CONFIG_FILE`, `AWS_CA_BUNDLE`, `AWS_USE_FIPS_ENDPOINT`, `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_STS`. The SDK never looks up AWS credentials for this call, so the helper cannot recurse into itself.
- Google auth libraries: `GOOGLE_APPLICATION_CREDENTIALS` names the ADC file. Without it, ADC is `~/.config/gcloud/application_default_credentials.json` (`%APPDATA%\gcloud\application_default_credentials.json` on Windows), then the metadata server.
- Proxies: the STS call and the calls to Google's OAuth and IAM Service Account Credentials endpoints honor `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. Requests to the metadata server never use a proxy.

## Google setup

Credentials that can produce the ID token without `--impersonate-service-account`:

- A service account key file, through `GOOGLE_APPLICATION_CREDENTIALS`.
- An ADC file of type `impersonated_service_account` or `external_account` (workload identity federation) that names a service account to impersonate.
- The metadata server, for the attached service account, on Compute Engine, GKE, Cloud Run, Cloud Run functions, App Engine and Cloud Build. On GKE, decode a token first (see [Troubleshooting](#troubleshooting)) and write the trust policy from the `azp`, `aud` and `sub` values you see.

The Google library cannot mint ID tokens from gcloud user credentials, which `gcloud auth application-default login` puts in the ADC location. The tool fails with `idtoken: unsupported credentials type` and a hint. Use them to impersonate a service account instead:

```sh
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com
gcloud iam service-accounts add-iam-policy-binding my-sa@my-project.iam.gserviceaccount.com \
  --member=user:you@example.com --role=roles/iam.serviceAccountOpenIdTokenCreator
```

Then pass `--impersonate-service-account my-sa@my-project.iam.gserviceaccount.com`. The role `roles/iam.serviceAccountOpenIdTokenCreator` holds the permission `iam.serviceAccounts.getOpenIdToken`; the broader `roles/iam.serviceAccountTokenCreator` also has it. Impersonation authenticates with your ADC, of any type, so the role must be granted to that principal.

## AWS setup

The trust policy names `accounts.google.com` as the federated principal. AWS defines these condition keys for tokens from Google, and a Google service account ID token fills them as follows:

| Condition key | Token claim | Value in a service account ID token |
| --- | --- | --- |
| `accounts.google.com:aud` | `azp` (or `aud` if there is no `azp`) | The service account's unique ID |
| `accounts.google.com:oaud` | `aud` | The `--audience` value, `sts.amazonaws.com` by default |
| `accounts.google.com:sub` | `sub` | The service account's unique ID |

Service account ID tokens carry `azp`, so `accounts.google.com:aud` is the unique ID, not the audience. If you change `--audience`, change `accounts.google.com:oaud` to match.

Find the unique ID, a number:

```sh
gcloud iam service-accounts describe my-sa@my-project.iam.gserviceaccount.com --format='value(uniqueId)'
```

Example trust policy (`trust.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "accounts.google.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "112233445566778899001",
          "accounts.google.com:oaud": "sts.amazonaws.com",
          "accounts.google.com:sub": "112233445566778899001"
        }
      }
    }
  ]
}
```

```sh
aws iam create-role --role-name gcp-workload --assume-role-policy-document file://trust.json
```

Attach permission policies to the role as usual.

## Operational notes

- Nothing is cached or written to disk. Every run fetches a new Google token and calls STS once.
- The AWS CLI does not cache `credential_process` output, so every `aws` command runs the helper. A long-running SDK process runs it again before `Expiration`. Use `--duration-seconds` to make sessions longer.
- Stdout carries live AWS credentials. Do not log or capture it. The tool never writes credentials or the Google token to stderr.

## Troubleshooting

Start here: copy the `credential_process` command line from `~/.aws/config`, run it in a shell with the same environment, and read stderr and the exit code. Exit code 2 is a problem with the command line; 1 means the Google or AWS step failed. The AWS CLI shows the same stderr as `Error when retrieving credentials from custom-process: ...`.

```sh
/usr/local/bin/gcp-aws-auth --role-arn arn:aws:iam::123456789012:role/gcp-workload --role-session-name my-workload --region us-east-1 > /dev/null
echo "exit code: $?"
```

**`unexpected argument "..." (all options are flags; check for a missing flag name or quoting)`.** The command line has a word that is not a flag or a flag value, often from a value with spaces or a stray quote in `~/.aws/config`. The AWS CLI rule: wrap a value that contains spaces in double quotes, and quote only the value.

**`idtoken: unsupported credentials type`.** ADC are gcloud user credentials, which cannot mint ID tokens. Add `--impersonate-service-account` and grant the role shown in [Google setup](#google-setup).

**`google: could not find default credentials`.** There is no ADC file and the machine is not on Google Cloud. Set `GOOGLE_APPLICATION_CREDENTIALS` to a credentials file, or run `gcloud auth application-default login` and use `--impersonate-service-account`.

**`impersonate: status code 403: ...` with `PERMISSION_DENIED` and `Permission 'iam.serviceAccounts.getOpenIdToken' denied on resource (or it may not exist)`.** Your ADC principal lacks that permission on the target service account, or the service account email is wrong. Check the email and grant `roles/iam.serviceAccountOpenIdTokenCreator` on that service account, as in [Google setup](#google-setup).

**`impersonate: status code 403: ...` with `SERVICE_DISABLED` and `... has not been used in project ... before or it is disabled`.** The IAM Service Account Credentials API is not enabled in the project named in the message. Enable `iamcredentials.googleapis.com` there.

**`STS AssumeRoleWithWebIdentity failed: <Code>: <message> (request ID <id>)`.** STS refused the call:

- Access denied, `InvalidIdentityToken`, `IDPRejectedClaim` or `ExpiredToken`: the token's claims do not meet the role's trust policy, the role ARN is wrong, or STS could not validate the token. Role names are case sensitive. Decode the token as shown below.
- `RegionDisabled`: STS is not activated in that region for the account. An administrator can activate it in the IAM console, or pass a different `--region`.

To see the claims STS checks, get the same kind of token the tool uses and decode its payload:

```sh
# With impersonation:
gcloud auth print-identity-token --impersonate-service-account=my-sa@my-project.iam.gserviceaccount.com \
  --audiences=sts.amazonaws.com --include-email > token.jwt
# On Google Cloud compute (metadata server):
curl -s -H "Metadata-Flavor: Google" \
  'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=sts.amazonaws.com' > token.jwt

python3 -c 'import base64,json,sys; p=open(sys.argv[1]).read().split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))),indent=2))' token.jwt
```

Compare `azp`, `aud` and `sub` with `accounts.google.com:aud`, `:oaud` and `:sub` in the trust policy. Delete `token.jwt` afterwards; it is valid for one hour.

**`loading AWS configuration: ...`.** The AWS SDK could not load its configuration, for example because `AWS_PROFILE` names a profile that does not exist. STS was not called.

**`timed out after 1m0s while <step> (see --timeout)`.** The named step did not finish in time. While fetching the Google token, check that the metadata server or the IAM Service Account Credentials API is reachable. While calling STS, check network, proxy and `AWS_ENDPOINT_URL_STS`. Raise `--timeout`, or set it to `0` to debug.

## Changes since 0.0.2

- New flags `--region`, `--duration-seconds` and `--timeout` (default one minute).
- Positional arguments are rejected with exit code 2. 0.0.2 ignored everything after the first positional argument, so a quoting mistake in `~/.aws/config` could drop flags without notice. Such a configuration now fails.
- A missing required flag exits with 2, not 1. Runtime failures still exit with 1.
- A response from STS without credentials is reported as an error; 0.0.2 crashed.
- gcloud user credentials as ADC produce a hint to use `--impersonate-service-account`.
- An invalid `--region` or a blank `--impersonate-service-account` is a usage error, caught before any network call.
- On success stderr stays empty, even when the AWS SDK would log a warning; 0.0.2 could print `SDK ... WARN` lines there.
- Built with Go 1.27, so macOS binaries need macOS 13 or later.
- Output format, existing flag names and defaults are unchanged.

## Development

Prerequisites: Go 1.27.4 or later and [golangci-lint](https://golangci-lint.run/). Run the same checks as CI before you push:

```sh
go mod tidy -diff
go vet ./...
go test -race ./...
golangci-lint run ./...
```

The `CI` workflow (`.github/workflows/ci.yml`) also runs govulncheck, builds every release target and builds the image.

The Go version lives in `go.mod`. The `Dockerfile` has a `GO_VERSION` build argument whose default must equal the `go` line in `go.mod`, and CI fails if they differ, so a Go upgrade changes both files.

Maintainers release with:

```sh
./release.sh [--build-only] <tag> [release_notes]
```

`--build-only` builds the binaries and `checksums.txt` into `dist/` and publishes nothing; it needs none of the following. A full release needs the GitHub CLI logged in, Docker logged in to Docker Hub with push rights to the image, a clean working tree, and HEAD pushed.

The image's final stage installs `ca-certificates`, so it runs a command on each target platform, and the arm images are built under emulation. Official BuildKit releases bundle QEMU emulators. Before anything is built or published, `release.sh` checks that its builder can run every target platform. If it cannot, the script stops and tells you how to enable emulation; Docker's documented remedy is:

```sh
docker run --privileged --rm tonistiigi/binfmt --install all
```

## References

- AWS Security Blog: [Access AWS using a Google Cloud Platform native workload identity](https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/)

## License

MIT. See [LICENSE](LICENSE).
