#!/bin/bash
# ztunnel image from an exact committed fork tree: release ztunnel binary on the
# previously used distroless ztunnel base (only /usr/local/bin/ztunnel replaced).
set -euo pipefail
python3 -c 'import json,sys; d=json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json")); sys.exit(0 if d.get("primaryCompileAllowed") is True else 75)' || { echo "BUILD SLOT UNAVAILABLE"; exit 75; }
SRC=/private/tmp/cmtc-opus-final-20261025/ztunnel
BASE=localhost/cmtc-ztunnel:provider-6ef34d6939
BUILDER=def7f2e8dac02fbe34556331944cd766aa7f2ea9b90784f083634d52b59edb0f
OUT=/private/tmp/cmtc-claude-opus-20261025/lab/images
[ -z "$(git -C $SRC status --porcelain --untracked-files=all)" ] || { echo "commit ztunnel source first" >&2; exit 1; }
SHA=$(git -C $SRC rev-parse HEAD); SHORT=${SHA:0:10}
IMAGE=localhost/cmtc-ztunnel:native-$SHORT
CTX=$OUT/zt-ctx-$SHORT; mkdir -p $CTX
podman --connection cmtc-ubuntu-build run --rm --name cmtc-claude-zt-image-build --platform linux/arm64 --cpus 3 --memory 6g \
  --security-opt label=disable -e CARGO_HOME=/cargo -e CARGO_BUILD_JOBS=3 \
  -v "$SRC:$SRC" -v /private/tmp/cmtc-ztunnel-enforcement/.git:/private/tmp/cmtc-ztunnel-enforcement/.git:ro \
  -v /private/tmp/cmtc-ztunnel-cargo-cache:/cargo -v $CTX:/ctx -w "$SRC" $BUILDER \
  sh -ec 'git config --global --add safe.directory "$PWD"; rustc --version
    # The bind mount changes stat data, not content: refresh a private index copy
    # (the shared .git stays read-only) so the embedded BuildStatus is accurate.
    cp "$(git rev-parse --git-path index)" /tmp/build-index; export GIT_INDEX_FILE=/tmp/build-index
    git update-index -q --refresh; git diff-index --quiet HEAD -- || { echo "tree content differs from HEAD" >&2; exit 1; }
    cargo clean --release -p ztunnel; cargo build --locked --release --bin ztunnel; cp out/rust/release/ztunnel /ctx/ztunnel'
cat > $CTX/Containerfile <<CF
FROM $BASE
COPY ztunnel /usr/local/bin/ztunnel
CF
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --file $CTX/Containerfile \
  --label org.opencontainers.image.revision=$SHA --label io.cmtc.build.profile=release-native \
  --tag $IMAGE $CTX
podman --connection cmtc-ubuntu-build image inspect $IMAGE > $OUT/zt-image-$SHORT.json
shasum -a 256 $CTX/ztunnel | tee $OUT/zt-binary-$SHORT.sha256
podman --connection cmtc-ubuntu-build run --rm --network none --platform linux/arm64 --entrypoint /usr/local/bin/ztunnel $IMAGE version 2>&1 | tee $OUT/zt-version-$SHORT.txt || true
podman --connection cmtc-ubuntu-build save --format docker-archive --output $OUT/ztunnel-$SHORT.tar $IMAGE
shasum -a 256 $OUT/ztunnel-$SHORT.tar | tee $OUT/ztunnel-$SHORT.tar.sha256
echo "IMAGE=$IMAGE"
