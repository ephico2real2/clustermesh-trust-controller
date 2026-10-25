#!/bin/bash
set -euo pipefail
src=/private/tmp/cmtc-spire-upstream
out=/private/tmp/cmtc-spire-workload-runtime-20261024
sha=$(git -C "$src" rev-parse HEAD)
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
test "$sha" = 28f6b8d84ade21c6accb32ba9689a3bdf64877ec
mkdir -p "$out/image-context"
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 4g --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -e GOMODCACHE=/modules -e SOURCE_SHA="$sha" -v "$src:/src:ro" -v "$out/image-context:/out" -v /private/tmp/cmtc-spire-go-cache:/cache -v /private/tmp/cmtc-spire-go-modules:/modules -w /src 9938d98f3809e02fb90c5cd30475a0e41e13e0965e89f1254828d98780606425 sh -ec '
 go version
 go build -trimpath -ldflags "-s -w -X github.com/spiffe/spire/pkg/common/version.githash=$SOURCE_SHA -linkmode external -extldflags -static" -o /out/spire-agent ./cmd/spire-agent
 file /out/spire-agent
 /out/spire-agent --version
' > "$out/static-compile.log" 2>&1
cat > "$out/image-context/Containerfile" <<IMAGE
FROM ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481
COPY --chown=1000:1000 --chmod=755 spire-agent /opt/spire/bin/spire-agent
LABEL org.opencontainers.image.source="https://github.com/ephico2real2/spire" org.opencontainers.image.revision="$sha" org.opencontainers.image.version="1.16.0-dev-$sha"
IMAGE
image=localhost/cmtc-spire-agent:workload-${sha:0:10}
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --jobs 2 --memory 2g -f "$out/image-context/Containerfile" -t "$image" "$out/image-context" > "$out/agent-image-build.log" 2>&1
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/agent-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m --entrypoint /opt/spire/bin/spire-agent "$image" --version > "$out/agent-version.txt" 2>&1
rg -F "$sha" "$out/agent-version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/agent-arm64.tar" "$image"
shasum -a 256 "$out/agent-arm64.tar" > "$out/agent-arm64.tar.sha256"
printf '0\n' > "$out/agent-build.exit"
