# Self-contained, multi-platform build: `docker build .` works from a clean
# checkout. The build stage runs natively on the build host and cross-compiles
# for the target platform; only the final stage's `apk add` runs on the target
# platform (under QEMU emulation for non-native platforms).

# Must equal the go line of go.mod (CI checks this); release.sh passes it.
ARG GO_VERSION=1.27.4

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY cmd ./cmd
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
ARG VERSION=dev
# Same flags as release.sh. linux/arm is linux/arm/v7, so GOARM=7.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ "$TARGETARCH" = "arm" ]; then \
        v="${TARGETVARIANT#v}"; export GOARM="${v:-7}"; \
    fi; \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/gcp-aws-auth ./cmd/gcp-aws-auth

# Alpine rather than scratch: people copy the binary out of this image or use
# a shell in it. ca-certificates (not just the base image's bundle) keeps
# update-ca-certificates working for images derived from this one.
FROM alpine:3.24
RUN apk add --no-cache ca-certificates
ARG VERSION=dev
LABEL org.opencontainers.image.source="https://github.com/phntom/gcp-aws-assume-role-with-web-identity-helper" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"
COPY --chmod=0644 LICENSE /usr/share/licenses/gcp-aws-auth/LICENSE
COPY --from=build /out/gcp-aws-auth /usr/bin/gcp-aws-auth
ENTRYPOINT ["/usr/bin/gcp-aws-auth"]
