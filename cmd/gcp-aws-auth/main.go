// Command gcp-aws-auth is an AWS credential_process helper. It obtains a
// Google OIDC ID token (from Application Default Credentials, the GCE metadata
// server, or by impersonating a service account) and exchanges it for
// temporary AWS credentials with STS AssumeRoleWithWebIdentity. The
// credentials are printed on stdout in the credential_process JSON format.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
)

// version is injected at build time with -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDeps())
	stop()
	os.Exit(code)
}

// productionDeps wires the real Google and AWS implementations.
func productionDeps() deps {
	g := googleTokens{}
	a := stsAssumer{}
	return deps{
		defaultIDToken:      g.defaultIDToken,
		impersonatedIDToken: g.impersonatedIDToken,
		assumeRole:          a.assumeRole,
	}
}

// versionString returns the version injected by the release build. Otherwise
// it returns the main module version that the Go toolchain recorded in the
// build info: for a build from a git checkout that is a VCS pseudo-version
// such as v0.0.0-20260210103840-85075da9346e+dirty (this repository's tags
// have no "v" prefix, so they do not become module versions). It returns
// "dev" when no version was recorded.
func versionString() string {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(version, info, ok)
}

func resolveVersion(injected string, info *debug.BuildInfo, ok bool) string {
	if injected != "" && injected != "dev" {
		return injected
	}
	if ok && info != nil {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}
