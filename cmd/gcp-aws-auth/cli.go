package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	progName           = "gcp-aws-auth"
	defaultAudience    = "sts.amazonaws.com"
	defaultTimeout     = time.Minute
	minDurationSeconds = 900
	maxDurationSeconds = 43200
)

// options holds the parsed command line.
type options struct {
	roleARN         string
	roleSessionName string
	impersonateSA   string
	audience        string
	region          string
	durationFlag    int   // as typed; validated into durationSeconds
	durationSeconds int32 // 0 means "not sent"
	timeout         time.Duration
	showVersion     bool
}

// durationValue is a time.Duration flag whose parse error tells the user
// what to type: a bare number such as "30" is rejected, not given a unit.
type durationValue struct{ d *time.Duration }

func (v durationValue) String() string {
	if v.d == nil {
		return "0s"
	}
	return v.d.String()
}

func (v durationValue) Set(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return errors.New("want a duration with a unit, such as 30s, 2m or 1m30s (or 0 to disable the limit)")
	}
	*v.d = d
	return nil
}

func newFlagSet(o *options) *flag.FlagSet {
	fs := flag.NewFlagSet(progName, flag.ContinueOnError)
	fs.SetOutput(io.Discard) // run reports errors and usage itself
	fs.StringVar(&o.roleARN, "role-arn", "", "ARN of the AWS IAM role to assume (required)")
	fs.StringVar(&o.roleSessionName, "role-session-name", "", "session name for the assumed role (required)")
	fs.StringVar(&o.impersonateSA, "impersonate-service-account", "",
		"email of a Google service account to impersonate when minting the ID token;\n"+
			"needed when Application Default Credentials are gcloud user credentials")
	fs.StringVar(&o.audience, "audience", defaultAudience, "audience of the Google ID token")
	fs.StringVar(&o.region, "region", "",
		"AWS region for the STS call (default: AWS_REGION, AWS_DEFAULT_REGION,\n"+
			"the active profile's region, then us-east-1)")
	fs.IntVar(&o.durationFlag, "duration-seconds", 0,
		fmt.Sprintf("session duration in seconds, %d..%d, and at most the role's maximum session\n"+
			"duration; 0 omits the parameter and STS uses its default of 3600 (one hour)",
			minDurationSeconds, maxDurationSeconds))
	o.timeout = defaultTimeout
	fs.Var(durationValue{&o.timeout}, "timeout",
		"time limit for the whole run, as a `duration` with a unit such as 30s, 2m or 1m30s;\n0 disables it")
	fs.BoolVar(&o.showVersion, "version", false, "print the version and exit")
	return fs
}

// validRegion accepts exactly what the STS client's endpoint binding accepts
// (service/sts endpoints.go bindRegion, via rulesfn.IsValidHostLabel with
// sub-domains allowed): one or more dot-separated labels, each 1 to 63
// letters, digits or hyphens, not starting or ending with a hyphen.
// Validating here rejects a bad --region before any network I/O.
func validRegion(region string) bool {
	for label := range strings.SplitSeq(region, ".") {
		if !smithyhttp.ValidHostLabel(label) || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// parseArgs parses and validates args without any I/O. It returns
// flag.ErrHelp for -h/--help; any other error is a usage error.
func parseArgs(args []string) (*options, error) {
	o := &options{}
	fs := newFlagSet(o)
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument %q (all options are flags; check for a missing flag name or quoting)", fs.Arg(0))
	}
	if o.showVersion {
		return o, nil
	}
	var missing []string
	if strings.TrimSpace(o.roleARN) == "" {
		missing = append(missing, "--role-arn")
	}
	if strings.TrimSpace(o.roleSessionName) == "" {
		missing = append(missing, "--role-session-name")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	if o.impersonateSA != "" && strings.TrimSpace(o.impersonateSA) == "" {
		return nil, errors.New("--impersonate-service-account must not be blank")
	}
	if o.audience == "" {
		return nil, errors.New("--audience must not be empty")
	}
	if o.region != "" && !validRegion(o.region) {
		return nil, fmt.Errorf("--region %q is not a valid region name (expected something like eu-west-1)", o.region)
	}
	if d := o.durationFlag; d != 0 {
		if d < minDurationSeconds || d > maxDurationSeconds {
			return nil, fmt.Errorf("--duration-seconds %d is out of range: use 0 or a value from %d to %d",
				d, minDurationSeconds, maxDurationSeconds)
		}
		o.durationSeconds = int32(d)
	}
	if o.timeout < 0 {
		return nil, fmt.Errorf("--timeout %s is negative: use a positive duration, or 0 to disable", o.timeout)
	}
	return o, nil
}

// printUsage writes the help text; callers pass a buffer and check the final write.
func printUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: %[1]s --role-arn ARN --role-session-name NAME [flags]

Obtains a Google OIDC ID token and exchanges it for temporary AWS credentials
with STS AssumeRoleWithWebIdentity. Meant to be run by the AWS SDKs and CLI as
a credential_process; the credentials are printed as JSON on stdout.

Exit status: 0 success, 1 runtime failure, 2 usage error.

Flags:
`, progName)
	fs := newFlagSet(&options{})
	fs.SetOutput(w)
	fs.PrintDefaults()
}
