#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-rebuild-20261024
sha=$(cat "$out/cmtc-source-sha.txt")
image=localhost/cmtc:observe-${sha:0:10}
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --build-arg BUILDPLATFORM=linux/arm64 --build-arg TARGETOS=linux --build-arg TARGETARCH=arm64 --jobs 1 --memory 3g \
 --env GOMAXPROCS=2 --env GOMEMLIMIT=1536MiB --env GOFLAGS=-p=2 --unsetenv GOMAXPROCS --unsetenv GOMEMLIMIT --unsetenv GOFLAGS \
 -v /private/tmp/cmtc-podman-spire-go-cache:/root/.cache/go-build -v "$out/cmtc-go-mod-cache:/go/pkg/mod" \
 --label "org.opencontainers.image.revision=$sha" --label org.opencontainers.image.source=https://github.com/ephico2real2/clustermesh-trust-controller \
 --label io.cmtc.build.toolchain=go1.27.1 -t "$image" "$out/cmtc-source" > "$out/cmtc-image-build.log" 2>&1
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/cmtc-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m "$image" --help > "$out/cmtc-help.txt" 2>&1
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/cmtc-arm64.tar" "$image"
shasum -a 256 "$out/cmtc-arm64.tar" > "$out/cmtc-arm64.tar.sha256"
printf '0\n' > "$out/cmtc-build.exit"
