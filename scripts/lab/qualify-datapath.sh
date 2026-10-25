#!/bin/sh
set -eu
cd /workspace
: "${CMTC_BPF_TEST_PRIVATE_NETNS:?Require an owned private test namespace}"
test "$CMTC_BPF_TEST_PRIVATE_NETNS" = 1
# Both are ordinary tests and actual kernel tests; no skipped prerequisites.
test -z "$(gofmt -l internal/datapath internal/metricsexposure cmd/cmtc-bpf-observer cmd/cmtc-bpf-fence)"
clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/fence.c -o /tmp/fence.o
export CMTC_FENCE_ELF=/tmp/fence.o
clang -target bpfel -O2 -g -Wall -Werror -c internal/datapath/bpf/observer.c -o /tmp/observer.o
export CMTC_BPF_ELF=/tmp/observer.o
CGO_ENABLED=0 go build -trimpath -o /tmp/cmtc-bpf-observer ./cmd/cmtc-bpf-observer
export CMTC_BPF_OBSERVER_BIN=/tmp/cmtc-bpf-observer
CGO_ENABLED=0 go build -trimpath -o /tmp/cmtc-bpf-fence ./cmd/cmtc-bpf-fence
export CMTC_BPF_FENCE_BIN=/tmp/cmtc-bpf-fence
go test -count=1 -race -v ./internal/datapath ./internal/metricsexposure ./cmd/cmtc-bpf-observer ./cmd/cmtc-bpf-fence
go test -count=1 -race -tags=cmtc_bpf_privileged -v ./internal/datapath
go vet ./internal/datapath ./internal/metricsexposure ./cmd/cmtc-bpf-observer ./cmd/cmtc-bpf-fence
go vet -tags=cmtc_bpf_privileged ./internal/datapath
sha256sum /tmp/fence.o /tmp/cmtc-bpf-fence
