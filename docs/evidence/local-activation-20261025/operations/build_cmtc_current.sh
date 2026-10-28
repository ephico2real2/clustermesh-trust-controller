#!/bin/bash
set -euo pipefail
python3 -c 'import json; assert json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json"))["primaryCompileAllowed"]'
SRC=/Users/olasumbo/gitRepos/clustermest-trust-controller
OUT=/private/tmp/cmtc-primary-operations-20261025
SHA=$(git -C "$SRC" rev-parse HEAD)
SHORT=${SHA:0:10}
CTX=$OUT/cmtc-$SHORT
mkdir -p "$CTX"
P=(podman --connection cmtc-ubuntu-build)
"${P[@]}" run --rm --name cmtc-primary-current-build --platform linux/arm64 --cpus 2 --memory 4g -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOTOOLCHAIN=local -e GOFLAGS=-p=2 -e GOCACHE=/cache -e GOMODCACHE=/modcache -e CGO_ENABLED=0 -e SOURCE_REVISION="$SHA" -v "/private/tmp/cmtc-primary-operations-20261025/source-cmtc-96cbc9eeca:/src:ro" -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v /private/tmp/cmtc-spire-go-modules:/modcache -v "$CTX:/out" -w /src f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 bash -ec 'go version; for target in cmtc lab-ca-init lab-identity-init; do go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/$target ./cmd/$target; done; go build -mod=readonly -trimpath -ldflags="-s -w -X main.sourceRevision=$SOURCE_REVISION" -o /out/cmtc-spire-registrar ./cmd/cmtc-spire-registrar'
RUNTIME=$("${P[@]}" image inspect gcr.io/distroless/static-debian13:nonroot --format '{{.Id}}')
printf 'FROM %s\nCOPY cmtc /cmtc\nCOPY lab-ca-init /lab-ca-init\nCOPY lab-identity-init /lab-identity-init\nUSER 65532:65532\nENTRYPOINT ["/cmtc"]\n' "$RUNTIME" > "$CTX/Containerfile.cmtc"
printf 'FROM %s\nCOPY cmtc-spire-registrar /cmtc-spire-registrar\nUSER 1000:1000\nWORKDIR /\nENTRYPOINT ["/cmtc-spire-registrar"]\n' "$RUNTIME" > "$CTX/Containerfile.registrar"
for role in cmtc registrar; do
 if [ "$role" = cmtc ]; then IMAGE=localhost/cmtc:current-$SHORT; else IMAGE=localhost/cmtc-spire-registrar:current-$SHORT; fi
 "${P[@]}" build --platform linux/arm64 --file "$CTX/Containerfile.$role" --label org.opencontainers.image.revision="$SHA" --tag "$IMAGE" "$CTX"
 "${P[@]}" image inspect "$IMAGE" > "$OUT/$role-image-$SHORT.json"
 "${P[@]}" save --format docker-archive --output "$OUT/$role-$SHORT.tar" "$IMAGE"
 shasum -a 256 "$OUT/$role-$SHORT.tar"
 echo "IMAGE=$IMAGE"
done
shasum -a 256 "$CTX/cmtc" "$CTX/cmtc-spire-registrar"
