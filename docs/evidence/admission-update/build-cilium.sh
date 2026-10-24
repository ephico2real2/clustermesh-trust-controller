#!/usr/bin/env bash
set -euo pipefail
cd /private/tmp/cilium-ztunnel-authorization-runtime
source_sha=$(git rev-parse HEAD)
image=localhost/cilium:admission-${source_sha:0:10}
[ -z "$(git status --porcelain --untracked-files=all)" ]
printf '%s %s\n' "${source_sha:0:10}" "$(git show -s --format=%cI HEAD)" > GIT_VERSION
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 3g --security-opt label=disable \
 -e GOMAXPROCS=2 -e GOMEMLIMIT=1536MiB -e GOFLAGS=-p=2 -e GOCACHE=/cache \
 -v "$PWD:/src" -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src/daemon \
 docker.io/library/golang@sha256:162be5298a40ed317005c8339c6de4d10d3eef336d66dc8e9259b03ab9d3a6d2 \
 bash -c 'make GIT_VERSION="$(cat /src/GIT_VERSION)" EXTRA_GO_BUILD_FLAGS=-buildvcs=false cilium-agent'
context=/private/tmp/cmtc-admission-20261024/cilium-context
mkdir -p "$context"
cp daemon/cilium-agent "$context/"
cat > "$context/Containerfile" <<'EOF'
FROM ghcr.io/ephico2real2/cilium-dev@sha256:15cc5402e93416e8ff71f24b79b0fc1e6b3837f0c4c216b0eb377b8d47b92d68
COPY cilium-agent /usr/bin/cilium-agent
EOF
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --file "$context/Containerfile" \
 --label "org.opencontainers.image.revision=$source_sha" \
 --label org.opencontainers.image.source=https://github.com/ephico2real2/cilium \
 --tag "$image" "$context"
podman --connection cmtc-ubuntu-build image inspect "$image" > /private/tmp/cmtc-admission-20261024/cilium-image.json
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m --entrypoint /usr/bin/cilium-agent "$image" --version > /private/tmp/cmtc-admission-20261024/cilium-version.txt
rg -F "${source_sha:0:10}" /private/tmp/cmtc-admission-20261024/cilium-version.txt
podman --connection cmtc-ubuntu-build save --format docker-archive --output /private/tmp/cmtc-admission-20261024/cilium-arm64.tar "$image"

shasum -a 256 /private/tmp/cmtc-admission-20261024/cilium-arm64.tar > /private/tmp/cmtc-admission-20261024/cilium-arm64.tar.sha256
printf "0\n" > /private/tmp/cmtc-admission-20261024/cilium-build.exit
