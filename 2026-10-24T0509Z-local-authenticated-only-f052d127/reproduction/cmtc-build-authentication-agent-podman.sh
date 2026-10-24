#!/usr/bin/env bash
set -euo pipefail
cd /private/tmp/cilium-ztunnel-authorization-runtime
source_sha=$(git rev-parse HEAD)
[ -z "$(git status --porcelain --untracked-files=no)" ]
printf '%s %s\n' "${source_sha:0:10}" "$(git show -s --format=%cI HEAD)" > GIT_VERSION
podman --connection podman-machine-default run --rm --platform linux/arm64 --cpus 1 --memory 1536m --security-opt label=disable \
 -e GOMAXPROCS=1 -e GOMEMLIMIT=768MiB -e GOFLAGS=-p=1 -e GOCACHE=/cache \
 -v "$PWD:/src" -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src/daemon \
 docker.io/library/golang@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 \
 bash -c 'make GIT_VERSION="$(cat /src/GIT_VERSION)" EXTRA_GO_BUILD_FLAGS=-buildvcs=false cilium-agent'
context=/private/tmp/cmtc-authentication-agent-podman-context
mkdir -p "$context"
cp daemon/cilium-agent "$context/"
cat > "$context/Containerfile" <<'CONTAINERFILE'
FROM ghcr.io/ephico2real2/cilium-dev@sha256:15cc5402e93416e8ff71f24b79b0fc1e6b3837f0c4c216b0eb377b8d47b92d68
COPY cilium-agent /usr/bin/cilium-agent
CONTAINERFILE
podman --connection podman-machine-default build --platform linux/arm64 --file "$context/Containerfile" \
 --label "org.opencontainers.image.revision=$source_sha" \
 --label org.opencontainers.image.source=https://github.com/ephico2real2/cilium \
 --tag localhost/cilium:require-mtls "$context"
podman --connection podman-machine-default save --format docker-archive --output /private/tmp/cmtc-authentication-agent-podman.tar localhost/cilium:require-mtls
podman --connection podman-machine-default image inspect localhost/cilium:require-mtls > /private/tmp/cmtc-authentication-agent-podman-image.json
podman --connection podman-machine-default run --rm --network none --memory 256m --entrypoint /usr/bin/cilium-agent localhost/cilium:require-mtls --version | tee /private/tmp/cmtc-authentication-agent-podman-version.txt
grep -Fq "${source_sha:0:10}" /private/tmp/cmtc-authentication-agent-podman-version.txt
