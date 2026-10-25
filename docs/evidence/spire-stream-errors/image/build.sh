#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-spire-stream-image-20261025
src=/private/tmp/cmtc-ztunnel-upstream
sha=$(git -C "$src" rev-parse HEAD)
test -z "$(git -C "$src" status --porcelain --untracked-files=all)"
image=localhost/cmtc-spire-workload-check:stream-${sha:0:10}
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 4g --security-opt label=disable -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS=2 -v "$src:$src" -v /private/tmp/cmtc-ztunnel-enforcement/.git:/private/tmp/cmtc-ztunnel-enforcement/.git:ro -v /private/tmp/cmtc-ztunnel-enforcement/out/rust:"$src/out/rust" -v /private/tmp/cmtc-ztunnel-cargo-cache:/cargo -w "$src" def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f sh -ec 'git config --global --add safe.directory "$PWD"; cp "$(git rev-parse --git-path index)" /tmp/cmtc-index; export GIT_INDEX_FILE=/tmp/cmtc-index; git update-index --refresh; test -z "$(git status --porcelain)"; git rev-parse HEAD; cargo clean -p ztunnel; cargo build --locked --example spire-workload-check; out/rust/debug/examples/spire-workload-check version' > "$out/compile.log" 2>&1
mkdir -p "$out/image-context"
cp /private/tmp/cmtc-ztunnel-enforcement/out/rust/debug/examples/spire-workload-check "$out/image-context/"
shasum -a 256 "$out/image-context/spire-workload-check" > "$out/binary.sha256"
cat > "$out/image-context/Containerfile" <<IMAGE
FROM gcr.io/distroless/cc-debian13@sha256:91e80685018de611a20450bed6b011c3d3242b3d9cc4452208121f342703ada0
COPY --chmod=755 spire-workload-check /usr/local/bin/spire-workload-check
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/spire-workload-check"]
LABEL org.opencontainers.image.source="https://github.com/ephico2real2/ztunnel" org.opencontainers.image.revision="$sha" io.cmtc.scope="native-credential-diagnostic-no-proxy"
IMAGE
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --jobs 2 --memory 2g -t "$image" -f "$out/image-context/Containerfile" "$out/image-context" > "$out/image-build.log" 2>&1
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m "$image" version > "$out/version.txt"
rg -F "$sha" "$out/version.txt"
rg -F 'BuildStatus:"Clean"' "$out/version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/credential-arm64.tar" "$image"
shasum -a 256 "$out/credential-arm64.tar" > "$out/credential-arm64.tar.sha256"
printf '0\n' > "$out/build.exit"
