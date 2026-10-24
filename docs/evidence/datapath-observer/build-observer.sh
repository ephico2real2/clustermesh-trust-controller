#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-observer-20261024
sha=b193510f206a8655a3f9c240728b71b0427a5b31
image=localhost/cmtc-bpf-observer:observe-${sha:0:10}
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --jobs 1 --memory 3g --env GOMAXPROCS=2 --env GOMEMLIMIT=1536MiB --env GOFLAGS=-p=2 --unsetenv GOMAXPROCS --unsetenv GOMEMLIMIT --unsetenv GOFLAGS --build-arg BUILD_IMAGE=f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 --build-arg SOURCE_SHA="$sha" -f "$out/committed-source/build/Containerfile.bpf-observer" -t "$image" "$out/committed-source"
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/observer-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none "$image" --version > "$out/observer-version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive --output "$out/observer-arm64.tar" "$image"
shasum -a 256 "$out/observer-arm64.tar" > "$out/observer-arm64.tar.sha256"
