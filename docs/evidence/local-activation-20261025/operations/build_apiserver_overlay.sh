#!/bin/bash
# clustermesh-apiserver DEV overlay from an exact committed Cilium source: only
# /usr/bin/clustermesh-apiserver is replaced on the deployed 42f89f83aa image
# (layer diff_ids verified identical to the running be2c7e1d arm64 manifest).
# etcd, etcd-config.yaml and the rest of the image are unchanged.
set -euo pipefail
python3 -c 'import json,sys; d=json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json")); sys.exit(0 if d.get("primaryCompileAllowed") is True else 75)' || { echo "BUILD SLOT UNAVAILABLE"; exit 75; }
SRC=/private/tmp/cmtc-opus-final-20261025/cilium
GITDIR=/private/tmp/cmtc-cilium-3pbs1q64/.git
BASE=ghcr.io/ephico2real2/cilium-dev:sha-42f89f83aa5a03ea80f7a2b8cece56b27f87385a-clustermesh-apiserver-arm64
OUT=/private/tmp/cmtc-claude-opus-20261025/lab/images
[ -z "$(git -C $SRC status --porcelain --untracked-files=all)" ] || { echo "commit Cilium source first" >&2; exit 1; }
SHA=$(git -C $SRC rev-parse HEAD); SHORT=${SHA:0:10}
IMAGE=localhost/cilium-clustermesh-apiserver:dev-overlay-$SHORT
CTX=$OUT/apiserver-ctx-$SHORT; mkdir -p $CTX
printf '%s %s\n' "$SHORT" "$(git -C $SRC show -s --format=%cI HEAD)" > $CTX/GIT_VERSION
podman --connection cmtc-ubuntu-build run --rm --name cmtc-claude-apiserver-build --platform linux/arm64 --cpus 2 --memory 4g \
  --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache \
  -v $SRC:$SRC -v $GITDIR:$GITDIR:ro -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v $CTX:/ctx -w $SRC/clustermesh-apiserver \
  f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  bash -ec "git config --global --add safe.directory $SRC; make GIT_VERSION=\"\$(cat /ctx/GIT_VERSION)\" EXTRA_GO_BUILD_FLAGS=-buildvcs=false clustermesh-apiserver; cp clustermesh-apiserver /ctx/clustermesh-apiserver; rm -f clustermesh-apiserver"
cat > $CTX/Containerfile <<CF
FROM $BASE
COPY clustermesh-apiserver /usr/bin/clustermesh-apiserver
CF
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --file $CTX/Containerfile \
  --label org.opencontainers.image.revision=$SHA --label cmtc.dev-overlay=clustermesh-apiserver-binary-only \
  --tag $IMAGE $CTX
podman --connection cmtc-ubuntu-build image inspect $IMAGE > $OUT/apiserver-image-$SHORT.json
shasum -a 256 $CTX/clustermesh-apiserver | tee $OUT/apiserver-binary-$SHORT.sha256
podman --connection cmtc-ubuntu-build run --rm --network none --platform linux/arm64 --entrypoint /usr/bin/clustermesh-apiserver $IMAGE version 2>&1 | tee $OUT/apiserver-version-$SHORT.txt
grep -F "$SHORT" $OUT/apiserver-version-$SHORT.txt
podman --connection cmtc-ubuntu-build run --rm --network none --platform linux/arm64 --entrypoint /usr/bin/clustermesh-apiserver $IMAGE etcdinit --help 2>&1 | grep -F -- "--etcd-create-ztunnel-membership-users" | tee $OUT/apiserver-etcdinit-flag-$SHORT.txt
podman --connection cmtc-ubuntu-build save --format docker-archive --output $OUT/apiserver-$SHORT.tar $IMAGE
shasum -a 256 $OUT/apiserver-$SHORT.tar | tee $OUT/apiserver-$SHORT.tar.sha256
echo "IMAGE=$IMAGE"
