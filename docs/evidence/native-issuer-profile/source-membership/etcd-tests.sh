#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-native-source-lease-20261025
etcd_image=43e1e8d08cbb
podman --connection cmtc-ubuntu-build image inspect "$etcd_image" > "$out/etcd-image.json"
task_etcd_id=$(podman --connection cmtc-ubuntu-build run -d --platform linux/arm64 --cpus 0.5 --memory 256m --pids-limit 256 --name cmtc-source-lease-etcd-20261025 --entrypoint /usr/local/bin/etcd "$etcd_image" --name default --data-dir /tmp/cmtc-etcd --listen-client-urls http://127.0.0.1:4002 --advertise-client-urls http://127.0.0.1:4002 --listen-peer-urls http://127.0.0.1:4003 --initial-advertise-peer-urls http://127.0.0.1:4003 --initial-cluster default=http://127.0.0.1:4003)
printf '%s\n' "$task_etcd_id" > "$out/etcd-container-id"
cleanup() {
 podman --connection cmtc-ubuntu-build logs "$task_etcd_id" > "$out/etcd-runtime.log" 2>&1 || true
 podman --connection cmtc-ubuntu-build inspect "$task_etcd_id" > "$out/etcd-container-final.json" || true
 podman --connection cmtc-ubuntu-build rm -f "$task_etcd_id" > "$out/etcd-cleanup.log"
}
trap cleanup EXIT
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --network container:"$task_etcd_id" --cpus 2 --memory 4g --security-opt label=disable -e INTEGRATION_TESTS=1 -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src cee8c5638bdedad0944780cd5dd7e3ff4f7b5c7e558d328d5412deacd364b905 sh -ec 'go test -race -count=3 -json ./pkg/kvstore -run "^Test(UpdateWithExplicitLeaseTTLIfLocked|LeaseTTLWriteHeadRejectsDelayedCommitAfterWithdrawalAndKeyRemoval|LeaseTTLWriteHeadRejectsOldOwnerAndExpiringHead)$"' > "$out/etcd-first.jsonl" 2>&1
