#!/bin/bash
# Agent-only DEV overlay from an exact committed Cilium source: rebuilds the
# cilium-agent binary and the runtime BPF sources (/var/lib/cilium/bpf) the
# agent compiles at load time. Operator, ClusterMesh API server and chart are
# NOT rebuilt. This is a live-integration build, not a qualified release.
set -euo pipefail
python3 -c 'import json,sys; d=json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json")); sys.exit(0 if d.get("primaryCompileAllowed") is True else 75)' || { echo "BUILD SLOT UNAVAILABLE"; exit 75; }
SRC=/private/tmp/cmtc-opus-final-20261025/cilium
GITDIR=/private/tmp/cmtc-cilium-3pbs1q64/.git
BASE=localhost/cilium:namespace-uid-4459d58ed3
OUT=/private/tmp/cmtc-claude-opus-20261025/lab/images
[ -z "$(git -C $SRC status --porcelain --untracked-files=all)" ] || { echo "commit Cilium source first" >&2; exit 1; }
SHA=$(git -C $SRC rev-parse HEAD); SHORT=${SHA:0:10}
IMAGE=localhost/cilium:dev-overlay-$SHORT
CTX=$OUT/ctx-$SHORT; mkdir -p $CTX
printf '%s %s\n' "$SHORT" "$(git -C $SRC show -s --format=%cI HEAD)" > $CTX/GIT_VERSION
podman --connection cmtc-ubuntu-build run --rm --name cmtc-claude-agent-build --platform linux/arm64 --cpus 2 --memory 4g \
  --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache \
  -v $SRC:$SRC -v $GITDIR:$GITDIR:ro -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v $CTX:/ctx -w $SRC/daemon \
  f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  bash -ec "git config --global --add safe.directory $SRC; make GIT_VERSION=\"\$(cat /ctx/GIT_VERSION)\" EXTRA_GO_BUILD_FLAGS=-buildvcs=false cilium-agent; cp cilium-agent /ctx/cilium-agent; rm -f cilium-agent"
rm -rf $CTX/bpf; mkdir -p $CTX/bpf
# Same runtime source set the base image carries (C/H sources only; no objects).
(cd $SRC/bpf && tar --exclude='*.o' --exclude='*.ll' --exclude='*.d' --exclude='tests' --exclude='.gitignore' -cf - .) | (cd $CTX/bpf && tar -xf -)
cat > $CTX/Containerfile <<CF
FROM $BASE
COPY cilium-agent /usr/bin/cilium-agent
COPY bpf/ /var/lib/cilium/bpf/
CF
podman --connection cmtc-ubuntu-build build --platform linux/arm64 --file $CTX/Containerfile \
  --label org.opencontainers.image.revision=$SHA --label cmtc.dev-overlay=agent-and-bpf-only \
  --tag $IMAGE $CTX
podman --connection cmtc-ubuntu-build image inspect $IMAGE > $OUT/image-$SHORT.json
podman --connection cmtc-ubuntu-build run --rm --network none --platform linux/arm64 --entrypoint /usr/bin/cilium-agent $IMAGE --version | tee $OUT/version-$SHORT.txt
grep -F "$SHORT" $OUT/version-$SHORT.txt
podman --connection cmtc-ubuntu-build save --format docker-archive --output $OUT/agent-$SHORT.tar $IMAGE
shasum -a 256 $OUT/agent-$SHORT.tar | tee $OUT/agent-$SHORT.tar.sha256
echo "IMAGE=$IMAGE"
