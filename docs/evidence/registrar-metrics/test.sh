#!/bin/bash
set -euo pipefail
root=/Users/olasumbo/gitRepos/clustermest-trust-controller
out=/private/tmp/cmtc-registrar-metrics-20261025
python3 -c 'import json; d=json.load(open("/private/tmp/cmtc-opus-final-20261025/review/BUILD_SLOT.json")); assert d.get("primaryCompileAllowed") and not d.get("claudeCompileAllowed")'
cd "$root"
git rev-parse HEAD > "$out/source-head"
git diff -- cmd/cmtc-spire-registrar internal/spireregistrar > "$out/source-tracked.patch"
podman --connection cmtc-ubuntu-build info --format 'arch={{.Host.Arch}} rootless={{.Host.Security.Rootless}}' > "$out/preflight.log"
podman --connection cmtc-ubuntu-build run --rm --name cmtc-primary-registrar-metrics --platform linux/arm64 --cpus 2 --memory 4g --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=3GiB -e GOFLAGS='-p=2 -mod=readonly' -e GOCACHE=/cache -v "$out/source:/src:ro" -v "$out:/out" -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -v /private/tmp/cmtc-spire-go-modules:/go/pkg/mod -w /src f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 sh -c '
set +e
go version > /out/toolchain.log
go test -race -count=1 -timeout=180s -json ./internal/spireregistrar ./cmd/cmtc-spire-registrar > /out/race.jsonl 2> /out/race.stderr
r=$?; echo $r > /out/race.exit
go vet ./internal/spireregistrar ./cmd/cmtc-spire-registrar > /out/vet.log 2>&1
v=$?; echo $v > /out/vet.exit
exit $((r || v))
' > "$out/container.log" 2>&1
