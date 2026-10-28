#!/usr/bin/env bash
# Runs the measurement plane's kernel tests (Go build tag cmtc_bpf_privileged) against the running kernel, in a
# disposable privileged container of the pinned Cilium builder: the tests create cgroups, a veth pair, a network
# namespace and BPF programs, and all of them go away with the container. These tests are not lab qualification
# (ADR-005, "Acceptance"); they prove the programs, the plane and the loader binary on a real kernel.
#
# Usage: scripts/measurement/test-kernel.sh
# GOMODCACHE must hold the module's dependencies (go mod download) and be visible to the container engine; the
# container has no network. Set CONTAINER_ENGINE=podman to use Podman instead of Docker.
set -euo pipefail

builder=quay.io/cilium/cilium-builder@sha256:97d3a0f90898e83c8e63712accb64518f50ae0c4709c423f047c7871e8710ad5
engine=${CONTAINER_ENGINE:-docker}
root=$(cd "$(dirname "$0")/../.." && pwd)
modcache=${GOMODCACHE:-$(go env GOMODCACHE)}

"$engine" run --rm --privileged --cgroupns private --network none \
  -e CMTC_BPF_TEST_PRIVATE_NETNS=1 -e HOME=/tmp -e GOFLAGS=-mod=mod -e GOPROXY=off -e GOTOOLCHAIN=local \
  -e GOMODCACHE=/gomod -e GOCACHE=/tmp/gocache \
  -v "$root:/workspace:ro" -v "$modcache:/gomod:ro" -w /workspace --entrypoint bash "$builder" -euo pipefail -c '
uname -r
CGO_ENABLED=0 go build -trimpath -o /tmp/cmtc-measure ./cmd/cmtc-measure
export CMTC_MEASURE_BIN=/tmp/cmtc-measure
go vet -tags=cmtc_bpf_privileged ./internal/measurement ./cmd/cmtc-measure
go test -count=1 -race -tags=cmtc_bpf_privileged -v ./internal/measurement
go test -count=1 -race ./internal/measurement ./internal/agent ./cmd/cmtc-measure
# The work of the loader in one second, per attached Pod, without the race detector.
go test -count=1 -tags=cmtc_bpf_privileged -run "^$" -bench BenchmarkPlaneTick -benchtime 100x ./internal/measurement
sha256sum internal/measurement/bpf/measure_bpfel.o /tmp/cmtc-measure
'
