#!/bin/bash
# SPIRE agent DEV overlay: the deployed agent image (exact config ID) with only
# /opt/spire/bin/spire-agent replaced by a version-stamped static build of the
# committed SPIRE source (DelegatedIdentity-only listener). Not a release.
set -euo pipefail
python3 -c 'import json,sys; d=json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json")); sys.exit(0 if d.get("primaryCompileAllowed") is True else 75)' || { echo "BUILD SLOT UNAVAILABLE"; exit 75; }
SRC=/private/tmp/cmtc-opus-final-20261025/spire
BASE_ID=707fcee4feff6cfc29478b7fbb86b4ad2a592784659b2b77c67b07fec53d0ff6
BASE=localhost/cmtc-spire-agent:workload-28f6b8d84a
OUT=/private/tmp/cmtc-claude-opus-20261025/lab/images
P="podman --connection cmtc-ubuntu-build"
[ -z "$(git -C $SRC status --porcelain --untracked-files=all)" ] || { echo "commit SPIRE source first" >&2; exit 1; }
SHA=$(git -C $SRC rev-parse HEAD); SHORT=${SHA:0:10}
[ "$($P image inspect $BASE --format '{{.Id}}')" = "$BASE_ID" ] || { echo "base image ID changed" >&2; exit 1; }
IMAGE=localhost/cmtc-spire-agent:delegated-$SHORT
CTX=$OUT/spire-ctx-$SHORT; mkdir -p $CTX
$P run --rm --name cmtc-claude-spire-agent-build --platform linux/arm64 --cpus 2 --memory 4g --network none \
  -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false -e GOCACHE=/cache -e GOMODCACHE=/modcache -e CGO_ENABLED=0 \
  -v $SRC:/src:ro -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v /private/tmp/cmtc-spire-go-modules:/modcache -v $CTX:/out -w /src \
  f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 \
  go build -trimpath -ldflags "-s -w -X github.com/spiffe/spire/pkg/common/version.githash=$SHA" -o /out/spire-agent ./cmd/spire-agent
shasum -a 256 $CTX/spire-agent | tee $CTX/spire-agent.sha256
cat > $CTX/Containerfile <<CF
FROM $BASE_ID
COPY spire-agent /opt/spire/bin/spire-agent
CF
$P build --platform linux/arm64 --file $CTX/Containerfile \
  --label org.opencontainers.image.revision=$SHA --label cmtc.dev-overlay=spire-agent-binary-only \
  --label cmtc.base-config=$BASE_ID --tag $IMAGE $CTX
$P image inspect $IMAGE > $OUT/spire-image-$SHORT.json
$P run --rm --network none --platform linux/arm64 --entrypoint /opt/spire/bin/spire-agent $IMAGE --version 2>&1 | tee $OUT/spire-version-$SHORT.txt
grep -F "$SHA" $OUT/spire-version-$SHORT.txt
$P save --format docker-archive --output $OUT/spire-agent-$SHORT.tar $IMAGE
shasum -a 256 $OUT/spire-agent-$SHORT.tar | tee $OUT/spire-agent-$SHORT.tar.sha256
echo "IMAGE=$IMAGE"
