#!/usr/bin/env bash
# Run from the MacBook; transfer the archive to the existing kind runtime.
set -euo pipefail
cd "$(dirname "$0")/../../.."
connection=${CMTC_PODMAN_CONNECTION:-podman-machine-default}
platform=${CMTC_BUILD_PLATFORM:-linux/arm64}
image=${CMTC_MTLS_FIXTURE_IMAGE:-localhost/cmtc:spire-podman}
out=${CMTC_MTLS_BUILD_OUTPUT:-.tmp/mtls-spike}
mkdir -p "$out"
git diff --quiet HEAD -- Dockerfile api internal cmd go.mod go.sum || {
  echo 'Commit image source changes before recording an exact-source build.' >&2; exit 1;
}
source_sha=$(git rev-parse HEAD)
args=(build --platform "$platform" --jobs 1 --memory "${CMTC_BUILD_MEMORY:-1536m}" --security-opt label=disable
  --env "GOMAXPROCS=${CMTC_BUILD_CPUS:-1}" --env "GOMEMLIMIT=${CMTC_GO_MEMORY:-768MiB}" --env GOFLAGS=-p=1
  --unsetenv GOMAXPROCS --unsetenv GOMEMLIMIT --unsetenv GOFLAGS
  --label "org.opencontainers.image.revision=$source_sha"
  --label org.opencontainers.image.source=https://github.com/ephico2real2/clustermesh-trust-controller
  --tag "$image" --file Dockerfile)
if [ -n "${CMTC_GO_CACHE:-}" ]; then args+=(--volume "$CMTC_GO_CACHE:/root/.cache/go-build"); fi
if [ -n "${CMTC_GO_MOD_CACHE:-}" ]; then args+=(--volume "$CMTC_GO_MOD_CACHE:/go/pkg/mod"); fi
podman --connection "$connection" info --format '{{.Host.OS}}/{{.Host.Arch}}'
podman --connection "$connection" "${args[@]}" .
podman --connection "$connection" image inspect "$image" > "$out/podman-image.json"
podman --connection "$connection" run --rm --network none --memory 256m --entrypoint /cmtc "$image" --help
podman --connection "$connection" save --format docker-archive --output "$out/cmtc-podman-image.tar" "$image"
printf 'Built %s from %s; archive: %s/cmtc-podman-image.tar\n' "$image" "$source_sha" "$out"
