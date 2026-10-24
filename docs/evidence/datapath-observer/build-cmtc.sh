#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-observer-20261024
sha=b193510f206a8655a3f9c240728b71b0427a5b31
image=localhost/cmtc:observe-${sha:0:10}
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --build-arg BUILDPLATFORM=linux/arm64 --build-arg TARGETOS=linux --build-arg TARGETARCH=arm64 --jobs 1 --memory 3g --env GOMAXPROCS=2 --env GOMEMLIMIT=1536MiB --env GOFLAGS=-p=2 --unsetenv GOMAXPROCS --unsetenv GOMEMLIMIT --unsetenv GOFLAGS --label "org.opencontainers.image.revision=$sha" --label org.opencontainers.image.source=https://github.com/ephico2real2/clustermesh-trust-controller --label io.cmtc.build.toolchain=go1.27.3 -f "$out/Containerfile.cmtc-qualified" -t "$image" "$out/committed-source"
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/cmtc-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m "$image" --help > "$out/cmtc-help.txt" 2>&1
podman --connection cmtc-ubuntu-build save --format docker-archive --output "$out/cmtc-arm64.tar" "$image"
shasum -a 256 "$out/cmtc-arm64.tar" > "$out/cmtc-arm64.tar.sha256"
