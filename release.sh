#!/bin/bash
set -e

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <tag_name> [release_notes]"
    exit 1
fi

TAG_NAME=$1
RELEASE_NOTES=${2:-"Release $TAG_NAME"}

DIST_DIR="dist"
mkdir -p "$DIST_DIR"

# Clean up previous builds
rm -f "$DIST_DIR"/*

echo "Building version $TAG_NAME..."

targets=(
    "linux/amd64"
    "linux/arm64"
    "linux/arm"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "windows/386"
)

for target in "${targets[@]}"; do
    GOOS=${target%/*}
    GOARCH=${target#*/}

    OUTPUT_NAME="gcp-aws-auth-${GOOS}-${GOARCH}"
    if [ "$GOOS" == "windows" ]; then
        OUTPUT_NAME+=".exe"
    fi

    echo "Building for $target..."
    env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-X main.version=$TAG_NAME" -o "$DIST_DIR/$OUTPUT_NAME" cmd/gcp-aws-auth/main.go
done

echo "Build complete. Artifacts are in $DIST_DIR/"

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo "Error: gh (GitHub CLI) is not installed or not in PATH."
    echo "Binaries have been built, but release cannot be created."
    exit 1
fi

echo "Creating GitHub release..."
gh release create "$TAG_NAME" "$DIST_DIR"/* --notes "$RELEASE_NOTES" --title "$TAG_NAME"

echo "Release $TAG_NAME published successfully!"
