FROM alpine:latest
RUN apk add --no-cache ca-certificates
ARG TARGETARCH
COPY dist/gcp-aws-auth-linux-${TARGETARCH} /usr/bin/gcp-aws-auth
RUN chmod +x /usr/bin/gcp-aws-auth
ENTRYPOINT ["/usr/bin/gcp-aws-auth"]
