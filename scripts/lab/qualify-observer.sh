#!/bin/sh
# Run only inside a disposable privileged Podman Linux container with PRIVATE
# network namespace, source root mounted at /workspace. Never --network=host.
set -eu
cd /workspace
: "${CMTC_BPF_TEST_PRIVATE_NETNS:?Set to 1 only for this owned private test namespace}"
test "$CMTC_BPF_TEST_PRIVATE_NETNS" = 1
clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/observer.c -o /tmp/cmtc-observer_bpfel.o
export CMTC_BPF_ELF=/tmp/cmtc-observer_bpfel.o
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o /tmp/cmtc-bpf-observer ./cmd/cmtc-bpf-observer
export CMTC_BPF_OBSERVER_BIN=/tmp/cmtc-bpf-observer
# A missing tool, unsupported kernel, unavailable verifier or absent test fixture
# is a failure. These test sources contain no t.Skip calls.
go test -count=1 -race -v ./internal/datapath ./cmd/cmtc-bpf-observer
go test -count=1 -race -tags=cmtc_bpf_privileged -v ./internal/datapath
go vet ./internal/datapath ./cmd/cmtc-bpf-observer
go vet -tags=cmtc_bpf_privileged ./internal/datapath
sha256sum /tmp/cmtc-observer_bpfel.o /tmp/cmtc-bpf-observer
