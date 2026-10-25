FROM docker.io/library/golang@sha256:fa72cb185c5fe16a8e23aa0ef9def3c4346663dc0f264143ee2d0941f891ef1a
RUN apk add --no-cache build-base libseccomp-dev git file
ENV CGO_ENABLED=1
LABEL io.cmtc.purpose="Pinned ARM64 SPIRE static build with musl"
