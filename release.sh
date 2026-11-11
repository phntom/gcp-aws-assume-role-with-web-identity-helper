#!/usr/bin/env bash
#
# Build and publish a release of gcp-aws-auth.
#
#   ./release.sh [--build-only] <tag_name> [release_notes]
#
# --build-only  vet, test, build the binaries and checksums into dist/, stop.
#               Needs only git and go; never calls gh or docker.
#
# Full mode, in this order:
#   1. preflight checks; nothing is built or published if any fails
#   2. go vet and go test
#   3. build the binaries and dist/checksums.txt
#   4. build and push the image under <tag> only (a failure publishes nothing)
#   5. create the GitHub release at the built commit, with all files
#   6. point <image>:latest at the manifest pushed in step 4 (registry-side)
#
# Environment:
#   ALLOW_DIRTY=1  skip the clean-working-tree check (full mode only).
#
# Go builds are hermetic: the toolchain is exactly the go line of go.mod, and
# build-affecting Go settings from the environment or 'go env -w' are ignored.
# Module-download settings (GOPROXY, GOPRIVATE, GOSUMDB, ...) are kept.
#
# Runs on Linux and macOS (bash 3.2, BSD userland).

set -euo pipefail

GH_REPO_NAME="phntom/gcp-aws-assume-role-with-web-identity-helper"
MODULE="github.com/phntom/gcp-aws-assume-role-with-web-identity-helper"
IMAGE="phntom/gcp-aws-assume-role-with-web-identity-helper"
PLATFORMS="linux/amd64,linux/arm64,linux/arm"
BUILDER="multiarch-builder"
REMOTE="origin"
PKG="./cmd/gcp-aws-auth"
DIST_DIR="dist"
TARGETS="linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/386"

# Settings that change what the go command builds. They are cleared from the
# environment, and the user's go env file is disabled (GOENV=off) after its
# module-download settings below have been carried over.
GO_BUILD_VARS="GOFLAGS GOEXPERIMENT GOFIPS140 GOROOT GOOS GOARCH
GOAMD64 GOARM GOARM64 GO386 GOMIPS GOMIPS64 GOPPC64 GORISCV64 GOWASM
CC CXX CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_FFLAGS CGO_LDFLAGS GO_EXTLINK_ENABLED
GOWORK GOCOVERDIR"
# Settings that only control where modules and caches come from.
GO_KEEP_VARS="GOPROXY GONOPROXY GOPRIVATE GOSUMDB GONOSUMDB GOINSECURE
GOAUTH GOVCS GOPATH GOMODCACHE GOCACHE GOTMPDIR"

PROG="${0##*/}"
USAGE="usage: ${PROG} [--build-only] <tag_name> [release_notes]"

die() {
    printf '%s: error: %s\n' "$PROG" "$*" >&2
    exit 1
}

usage_error() {
    printf '%s: %s\n%s\n' "$PROG" "$*" "$USAGE" >&2
    exit 2
}

step() {
    printf '\n==> %s\n' "$*"
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "'$1' is not installed or not on PATH; $2"
}

# ---------------------------------------------------------------- arguments

BUILD_ONLY=0
if [ "$#" -gt 0 ]; then
    case "$1" in
        --build-only) BUILD_ONLY=1; shift ;;
        -h | --help) printf '%s\n' "$USAGE"; exit 0 ;;
        *) ;;
    esac
fi

[ "$#" -ge 1 ] || usage_error "missing <tag_name>"
[ "$#" -le 2 ] || usage_error "too many arguments"

TAG="$1"
NOTES="${2:-Release ${TAG}}"

# A misplaced flag must never turn into release notes of a full release.
if [ "$#" -eq 2 ] && [ "$2" = "--build-only" ]; then
    usage_error "--build-only must come before the tag"
fi

case "$TAG" in
    -*) usage_error "invalid tag '${TAG}': options must come before the tag, and a tag cannot start with '-'" ;;
    latest) usage_error "invalid tag 'latest': the script maintains ${IMAGE}:latest itself; use a version" ;;
    *) ;;
esac

# Docker's tag grammar is the narrower one: [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}.
DOCKER_TAG_RE='^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
if ! [[ "$TAG" =~ $DOCKER_TAG_RE ]]; then
    usage_error "invalid tag '${TAG}': a Docker tag is 1-128 characters of [A-Za-z0-9_.-] and cannot start with '.' or '-'"
fi

need git "install git"
need go "install Go (see go.mod for the version)"

# git forbids some names Docker allows (for example 'a..b', 'x.lock', 'a.').
git check-ref-format "refs/tags/${TAG}" ||
    usage_error "invalid tag '${TAG}': it is not a valid git tag name (see 'git help check-ref-format')"

# Run from the repository root. Through a symlink, dirname "$0" is the
# symlink's directory, which this check rejects.
cd "$(dirname "$0")"
if ! [ -f go.mod ] || ! [ -d cmd/gcp-aws-auth ] ||
    [ "$(awk '$1 == "module" { print $2; exit }' go.mod)" != "$MODULE" ]; then
    die "$(pwd) is not the root of the ${MODULE} repository; run release.sh by its real path in the repository (not through a symlink)"
fi

GO_VERSION="$(awk '$1 == "go" { print $2; exit }' go.mod)"
[ -n "$GO_VERSION" ] || die "go.mod has no 'go' line"

# sha256sum on Linux, shasum on macOS; both print the same format.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
    SHA256="shasum -a 256"
else
    die "neither 'sha256sum' nor 'shasum' is on PATH; install coreutils or perl's shasum"
fi

# ------------------------------------------------------- hermetic Go setup

# Exactly the toolchain go.mod names; downloaded through GOPROXY if needed.
# This overrides GOTOOLCHAIN from the environment (CI sets 'local') and from
# 'go env -w'; with the matching Go installed, nothing is downloaded.
export GOTOOLCHAIN="go${GO_VERSION}"
for var in $GO_BUILD_VARS; do
    unset "$var"
done

# Carry over the effective module-download settings (from the environment or
# 'go env -w'), then stop reading the user's go env file.
for var in $GO_KEEP_VARS; do
    val="$(go env "$var")" ||
        die "'go env ${var}' failed; check your Go installation and settings (the Go ${GO_VERSION} toolchain may need downloading)"
    export "${var}=${val}"
done
export GOENV=off
export GOWORK=off
export CGO_ENABLED=0

actual="$(go env GOVERSION)" || die "cannot run the Go ${GO_VERSION} toolchain"
[ "$actual" = "go${GO_VERSION}" ] ||
    die "the go command runs ${actual}, not go${GO_VERSION} from go.mod; install Go ${GO_VERSION} or allow toolchain downloads"

# ---------------------------------------------------------------- preflight

# Runs 'RUN true' on <platform> in the final stage's base image: proves the
# builder can execute that platform even when 'docker buildx inspect' does not
# list it (BuildKit's bundled QEMU emulators are not listed). Local only.
probe_platform() {
    local builder="$1" platform="$2" base dir rc=0
    base="$(awk 'toupper($1) == "FROM" { img = $2 } END { print img }' Dockerfile)"
    dir="$(mktemp -d "${TMPDIR:-/tmp}/release-probe.XXXXXX")" || return 1
    printf 'FROM %s\nRUN true\n' "$base" >"${dir}/Dockerfile"
    docker buildx build --builder "$builder" --platform "$platform" \
        --no-cache --progress quiet "$dir" >/dev/null 2>&1 || rc=$?
    rm -rf "$dir"
    return "$rc"
}

# Fails unless the builder can run every platform in PLATFORMS; linux/arm is
# linux/arm/v7. A platform counts if 'docker buildx inspect' reports it, or
# else if a one-line probe build on it succeeds.
check_builder_platforms() {
    local builder="$1" inspect supported want missing p
    inspect="$(docker buildx inspect --bootstrap "$builder" 2>&1)" || {
        printf 'cannot start the buildx builder %s: %s\n' "$builder" "$(printf '%s\n' "$inspect" | tail -n 1)"
        return 2
    }
    # One "Platforms:" line per node; '*' marks platforms set by hand.
    supported="$(printf '%s\n' "$inspect" |
        sed -n 's/^[[:space:]]*Platforms:[[:space:]]*//p' |
        tr ',' '\n' | tr -d ' *\t')"
    missing=""
    for p in $(printf '%s\n' "$PLATFORMS" | tr ',' ' '); do
        case "$p" in
            linux/arm) want="linux/arm/v7" ;;
            *) want="$p" ;;
        esac
        if printf '%s\n' "$supported" | grep -Fx -e "$want" -e "${want}/v8" >/dev/null; then
            continue
        fi
        if probe_platform "$builder" "$want"; then
            printf '  %s: not listed by the builder, but a probe build ran on it (emulated)\n' "$want" >&2
        else
            missing="${missing} ${want}"
        fi
    done
    if [ -n "$missing" ]; then
        printf 'builder %s cannot run:%s (a probe build failed; it lists: %s)\n' \
            "$builder" "$missing" "$(printf '%s\n' "$supported" | tr '\n' ' ')"
        return 1
    fi
}

if [ "$BUILD_ONLY" -eq 0 ]; then
    step "Preflight checks"

    need gh "install the GitHub CLI (https://cli.github.com), or use --build-only"
    need docker "install Docker with buildx, or use --build-only"
    docker buildx version >/dev/null 2>&1 ||
        die "'docker buildx' is not available; install the Docker buildx plugin"

    [ "$(git rev-parse --show-toplevel 2>/dev/null)" = "$(pwd -P)" ] ||
        die "$(pwd -P) is not the top of a git work tree; run the release from a clone of ${GH_REPO_NAME}"

    gh auth status >/dev/null 2>&1 ||
        die "the GitHub CLI is not logged in; run 'gh auth login' and retry"

    # The release goes to GH_REPO_NAME (every gh call passes --repo), so the
    # branches and tags checked below must come from that repository too.
    # Read the raw value: 'git remote get-url' would apply insteadOf rewrites.
    origin_url="$(git config --get "remote.${REMOTE}.url")" ||
        die "no remote '${REMOTE}' is configured; add it: git remote add ${REMOTE} git@github.com:${GH_REPO_NAME}.git"
    origin_lc="$(printf '%s' "$origin_url" | tr '[:upper:]' '[:lower:]')"
    repo_lc="$(printf '%s' "$GH_REPO_NAME" | tr '[:upper:]' '[:lower:]')"
    case "$origin_lc" in
        "git@github.com:${repo_lc}" | "git@github.com:${repo_lc}.git" | \
            "ssh://git@github.com/${repo_lc}" | "ssh://git@github.com/${repo_lc}.git" | \
            "https://github.com/${repo_lc}" | "https://github.com/${repo_lc}.git" | \
            "https://github.com/${repo_lc}/") ;;
        *) die "remote '${REMOTE}' is '${origin_url}', not github.com/${GH_REPO_NAME}; run from a clone whose ${REMOTE} is that repository" ;;
    esac

    if [ "${ALLOW_DIRTY:-0}" = "1" ]; then
        echo "ALLOW_DIRTY=1: skipping the clean-working-tree check"
    elif [ -n "$(git status --porcelain --untracked-files=all)" ]; then
        die "the working tree has uncommitted or untracked files; commit or remove them, or set ALLOW_DIRTY=1"
    fi

    COMMIT="$(git rev-parse --verify 'HEAD^{commit}')" ||
        die "HEAD does not point at a commit; commit something first"

    # HEAD must be on the remote, or GitHub cannot create the tag at it.
    # Read-only: compare with the remote's branch heads without fetching.
    remote_heads="$(git ls-remote --heads "$REMOTE")" ||
        die "cannot list branches of remote '${REMOTE}'; check the remote and your network"
    on_remote=0
    for head in $(printf '%s\n' "$remote_heads" | awk '{ print $1 }'); do
        if git cat-file -e "${head}^{commit}" 2>/dev/null &&
            git merge-base --is-ancestor "$COMMIT" "$head" 2>/dev/null; then
            on_remote=1
            break
        fi
    done
    [ "$on_remote" -eq 1 ] ||
        die "HEAD ${COMMIT} is not on any branch of '${REMOTE}'; push it first (or 'git fetch ${REMOTE}' if it is already pushed)"

    if printf '%s\n' "$remote_heads" | awk '{ print $2 }' | grep -Fx "refs/heads/${TAG}" >/dev/null; then
        die "'${TAG}' is also a branch on '${REMOTE}'; a tag of the same name makes refs ambiguous, choose another tag"
    fi

    remote_tag="$(git ls-remote --tags "$REMOTE" "refs/tags/${TAG}")" ||
        die "cannot list tags of remote '${REMOTE}'; check the remote and your network"
    [ -z "$remote_tag" ] ||
        die "tag '${TAG}' already exists on '${REMOTE}'; choose a new tag"

    if local_tag="$(git rev-parse -q --verify "refs/tags/${TAG}^{commit}")"; then
        [ "$local_tag" = "$COMMIT" ] ||
            die "a local tag '${TAG}' points at ${local_tag}, not HEAD ${COMMIT}; delete it (git tag -d ${TAG}) or choose another tag"
    fi

    if view_out="$(gh release view "$TAG" --repo "$GH_REPO_NAME" 2>&1)"; then
        die "a GitHub release named '${TAG}' already exists in ${GH_REPO_NAME} (possibly a draft); choose a new tag, or delete it with 'gh release delete ${TAG} --repo ${GH_REPO_NAME}'"
    fi
    case "$view_out" in
        *"not found"* | *"Not Found"*) ;;
        *) die "could not check whether release '${TAG}' exists: $(printf '%s' "$view_out" | head -n 1)" ;;
    esac

    # Local only: create the builder if missing (never switch the default
    # builder), start it, and check it can build every platform.
    if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
        docker buildx create --name "$BUILDER" --driver docker-container >/dev/null ||
            die "cannot create the buildx builder '${BUILDER}'"
    fi
    platform_rc=0
    platform_problem="$(check_builder_platforms "$BUILDER")" || platform_rc=$?
    case "$platform_rc" in
        0) ;;
        1) die "${platform_problem}. The image's final stage runs on each target platform, so non-native ones need QEMU emulation: Docker Desktop has it built in; on Linux run 'docker run --privileged --rm tonistiigi/binfmt --install arm64,arm', then 'docker buildx stop ${BUILDER}' so the builder detects the new platforms when it restarts" ;;
        *) die "${platform_problem}; check that Docker is running, or remove the builder with 'docker buildx rm ${BUILDER}' so the script recreates it" ;;
    esac

    echo "OK: releasing ${TAG} at ${COMMIT} to ${GH_REPO_NAME} with Go ${GO_VERSION}"
fi

# ------------------------------------------------------------- vet and test

step "go vet and go test (Go ${GO_VERSION})"
go vet ./...
go test ./...

# -------------------------------------------------------------------- build

step "Building ${TAG}"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

ARTIFACTS=""
for target in $TARGETS; do
    goos="${target%/*}"
    goarch="${target#*/}"
    out="gcp-aws-auth-${goos}-${goarch}"
    if [ "$goos" = "windows" ]; then
        out="${out}.exe"
    fi
    # linux/arm is ARMv7, which is also what Docker's linux/arm means.
    goarm=""
    if [ "$goarch" = "arm" ]; then
        goarm="7"
    fi

    echo "  ${target} -> ${DIST_DIR}/${out}"
    env GOOS="$goos" GOARCH="$goarch" GOARM="$goarm" \
        go build -trimpath -ldflags "-s -w -X main.version=${TAG}" \
        -o "${DIST_DIR}/${out}" "$PKG"
    ARTIFACTS="${ARTIFACTS} ${out}"
done

# shellcheck disable=SC2086 # SHA256 and ARTIFACTS are deliberately word-split.
(cd "$DIST_DIR" && $SHA256 $ARTIFACTS >checksums.txt)
echo "  checksums -> ${DIST_DIR}/checksums.txt"

if [ "$BUILD_ONLY" -eq 1 ]; then
    step "Build complete; artifacts are in ${DIST_DIR}/ (--build-only: nothing published)"
    exit 0
fi

# ------------------------------------------------------------------ publish

RETAG_CMD="docker buildx imagetools create --builder ${BUILDER} --tag ${IMAGE}:latest ${IMAGE}:${TAG}"

step "Building and pushing image ${IMAGE}:${TAG} for ${PLATFORMS}"
docker buildx build \
    --builder "$BUILDER" \
    --platform "$PLATFORMS" \
    --build-arg "GO_VERSION=${GO_VERSION}" \
    --build-arg "VERSION=${TAG}" \
    --tag "${IMAGE}:${TAG}" \
    --push \
    . ||
    die "the image build or push failed. Nothing from this run is public: no image tag ${TAG}, no GitHub release, ${IMAGE}:latest unchanged. Fix the cause (for example 'docker login') and re-run ./release.sh ${TAG}"

step "Creating GitHub release ${TAG} in ${GH_REPO_NAME} at ${COMMIT}"
release_files=""
for f in $ARTIFACTS checksums.txt; do
    release_files="${release_files} ${DIST_DIR}/${f}"
done
# shellcheck disable=SC2086 # release_files is a space-separated list without spaces in names.
gh release create "$TAG" \
    --repo "$GH_REPO_NAME" \
    --target "$COMMIT" \
    --title "$TAG" \
    --notes "$NOTES" \
    $release_files ||
    die "'gh release create' failed. Now public: image ${IMAGE}:${TAG} only. There is no GitHub release and ${IMAGE}:latest is unchanged. Fix the cause and re-run ./release.sh ${TAG} (safe: it rebuilds and re-pushes the same tag). If 'gh release view ${TAG} --repo ${GH_REPO_NAME}' shows a leftover draft, delete it first with 'gh release delete ${TAG} --repo ${GH_REPO_NAME}'"

step "Pointing ${IMAGE}:latest at ${IMAGE}:${TAG}"
# Registry-side copy of the pushed index: no rebuild, same digest.
docker buildx imagetools create \
    --builder "$BUILDER" \
    --tag "${IMAGE}:latest" \
    "${IMAGE}:${TAG}" ||
    die "retagging failed. Now public: GitHub release ${TAG} and image ${IMAGE}:${TAG}; ${IMAGE}:latest still points at the previous release. Do not re-run the script; once fixed, run: ${RETAG_CMD}"

step "Released ${TAG}: GitHub release, ${IMAGE}:${TAG} and ${IMAGE}:latest"
