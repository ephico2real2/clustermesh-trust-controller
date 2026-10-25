#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-native-provider-image-20261024
src=/private/tmp/cmtc-ztunnel-upstream
sha=$(git -C "$src" rev-parse HEAD)
[ -z "$(git -C "$src" status --porcelain --untracked-files=all)" ]
image=localhost/cmtc-ztunnel:provider-${sha:0:10}
# Rebuild this package so build.rs refreshes source metadata after the commit.
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 6g --security-opt label=disable \
 -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS=2 \
 -v "$src:$src" -v /private/tmp/cmtc-ztunnel-enforcement/.git:/private/tmp/cmtc-ztunnel-enforcement/.git:ro \
 -v /private/tmp/cmtc-ztunnel-enforcement/out/rust:"$src/out/rust" \
 -v /private/tmp/cmtc-ztunnel-cargo-cache:/cargo -w "$src" \
 def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f \
 sh -ec 'git config --global --add safe.directory "$PWD"; cp "$(git rev-parse --git-path index)" /tmp/cmtc-index; export GIT_INDEX_FILE=/tmp/cmtc-index; git update-index --refresh; test -z "$(git status --porcelain)"; git rev-parse HEAD; cargo clean -p ztunnel; cargo build --locked --bin ztunnel; out/rust/debug/ztunnel version' > "$out/ztunnel-compile.log" 2>&1
mkdir -p "$out/ztunnel-context/arm64"
cp /private/tmp/cmtc-ztunnel-enforcement/out/rust/debug/ztunnel "$out/ztunnel-context/arm64/ztunnel"
cp "$src/Dockerfile" "$out/ztunnel-context/Dockerfile"
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --build-arg TARGETARCH=arm64 \
 --build-arg BASE_IMAGE=gcr.io/distroless/cc-debian13@sha256:91e80685018de611a20450bed6b011c3d3242b3d9cc4452208121f342703ada0 \
 --label org.opencontainers.image.source=https://github.com/ephico2real2/ztunnel \
 --label "org.opencontainers.image.revision=$sha" --label io.cmtc.build.profile=debug-native-profile-provider \
 -t "$image" "$out/ztunnel-context" > "$out/ztunnel-image-build.log" 2>&1
podman --connection cmtc-ubuntu-build image inspect "$image" > "$out/ztunnel-image.json"
podman --connection cmtc-ubuntu-build run --rm --network none --memory 256m "$image" version > "$out/ztunnel-version.txt"
rg -F "$sha" "$out/ztunnel-version.txt"
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/ztunnel-arm64.tar" "$image"
shasum -a 256 "$out/ztunnel-arm64.tar" > "$out/ztunnel-arm64.tar.sha256"
printf '0\n' > "$out/ztunnel-build.exit"
