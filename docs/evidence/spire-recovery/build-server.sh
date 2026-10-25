#!/bin/bash
set -euo pipefail
src=/private/tmp/cmtc-spire-upstream
out=/private/tmp/cmtc-spire-recovery-20261024
sha=$(git -C "$src" rev-parse HEAD)
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
mkdir -p "$out/image-context"
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 4g --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -e GOMODCACHE=/modules -e SOURCE_SHA="$sha" -v "$src:/src:ro" -v "$out/image-context:/out" -v /private/tmp/cmtc-spire-go-cache:/cache -v /private/tmp/cmtc-spire-go-modules:/modules -w /src 9938d98f3809e02fb90c5cd30475a0e41e13e0965e89f1254828d98780606425 sh -ec '
 go version
 go build -trimpath -ldflags "-s -w -X github.com/spiffe/spire/pkg/common/version.githash=$SOURCE_SHA -linkmode external -extldflags -static" -o /out/spire-server ./cmd/spire-server
 file /out/spire-server
 /out/spire-server --version
' > "$out/static-compile.log" 2>&1
cat > "$out/image-context/Containerfile" <<IMAGE
FROM ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384
COPY --chown=1000:1000 --chmod=755 spire-server /opt/spire/bin/spire-server
LABEL org.opencontainers.image.source="https://github.com/ephico2real2/spire" org.opencontainers.image.revision="$sha" org.opencontainers.image.version="1.16.0-dev-$sha"
IMAGE
image=localhost/cmtc-spire-server:journal-${sha:0:10}
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --jobs 2 --memory 2g -f "$out/image-context/Containerfile" -t "$image" "$out/image-context" > "$out/server-image-build.log" 2>&1
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/server-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m --entrypoint /opt/spire/bin/spire-server "$image" --version > "$out/server-version.txt" 2>&1
rg -F "$sha" "$out/server-version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/server-arm64.tar" "$image"
shasum -a 256 "$out/server-arm64.tar" > "$out/server-arm64.tar.sha256"
printf '0\n' > "$out/server-build.exit"
