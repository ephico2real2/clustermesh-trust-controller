#!/usr/bin/env bash
set -euo pipefail
out=/private/tmp/cmtc-rebuild-20261024
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --privileged --cpus 2 --memory 4g --security-opt label=disable -e PRIVILEGED_TESTS=1 -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src localhost/cmtc-cilium-test:local sh -ec 'gofmt -w pkg/ztunnel/admission/cell.go pkg/ztunnel/admission/cell_test.go pkg/ztunnel/admission/required*; go test -race -count=1 -v ./pkg/ztunnel/... ./pkg/endpoint/api; go vet ./pkg/ztunnel/... ./pkg/endpoint/api' > "$out/admission-persistence-qualified.log" 2>&1
printf '0\n' > "$out/admission-persistence-qualified.exit"
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 6g --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=4GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src docker.io/golangci/golangci-lint@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481 golangci-lint run ./pkg/ztunnel/admission ./pkg/endpoint/api > "$out/admission-persistence-lint-qualified.log" 2>&1
printf '0\n' > "$out/admission-persistence-lint-qualified.exit"
