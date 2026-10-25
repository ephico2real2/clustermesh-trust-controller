#!/bin/bash
set -euo pipefail
SRC=/private/tmp/cmtc-opus-final-20261025/cilium
GITDIR=/private/tmp/cmtc-cilium-3pbs1q64/.git
OUT=/private/tmp/cmtc-primary-operations-20261025
SHA=$(git -C "$SRC" rev-parse HEAD); SHORT=${SHA:0:10}; CTX=$OUT/operator-$SHORT
mkdir -p "$CTX"
P=(podman --connection cmtc-ubuntu-build)
printf '%s %s\n' "$SHORT" "$(git -C "$SRC" show -s --format=%cI HEAD)" > "$CTX/GIT_VERSION"
"${P[@]}" run --rm --name cmtc-primary-operator-build --platform linux/arm64 --cpus 2 --memory 4g --network none -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v "$SRC:$SRC" -v "$GITDIR:$GITDIR:ro" -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v "$CTX:/ctx" -w "$SRC" f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 bash -ec 'git config --global --add safe.directory "$PWD"; go test -race -count=1 -json ./operator/pkg/ztunnel/config ./operator/pkg/ztunnel/spire > /ctx/test.jsonl; go vet ./operator/pkg/ztunnel/config ./operator/pkg/ztunnel/spire; cd operator; make GIT_VERSION="$(cat /ctx/GIT_VERSION)" EXTRA_GO_BUILD_FLAGS=-buildvcs=false cilium-operator-generic; cp cilium-operator-generic /ctx/cilium-operator-generic; rm -f cilium-operator-generic'
BASE=ghcr.io/ephico2real2/cilium-dev@sha256:5cfa1b276298f4a97bf4e73eb068e87fc730874975da137754062b838ac63aa7
"${P[@]}" pull --platform linux/arm64 "$BASE"
printf 'FROM %s\nCOPY cilium-operator-generic /usr/bin/cilium-operator-generic\nENTRYPOINT ["/usr/bin/cilium-operator-generic"]\n' "$BASE" > "$CTX/Containerfile"
IMAGE=localhost/cilium-operator:dev-overlay-$SHORT
"${P[@]}" build --platform linux/arm64 --file "$CTX/Containerfile" --label org.opencontainers.image.revision="$SHA" --tag "$IMAGE" "$CTX"
"${P[@]}" image inspect "$IMAGE" > "$OUT/operator-image-$SHORT.json"
"${P[@]}" run --rm --network none --entrypoint /usr/bin/cilium-operator-generic "$IMAGE" --version | tee "$OUT/operator-version-$SHORT.txt"
"${P[@]}" run --rm --network none --entrypoint /usr/bin/cilium-operator-generic "$IMAGE" --help | grep -F -- --ztunnel-spire-external-exact-registrar
"${P[@]}" save --format docker-archive --output "$OUT/operator-$SHORT.tar" "$IMAGE"
shasum -a 256 "$OUT/operator-$SHORT.tar"
