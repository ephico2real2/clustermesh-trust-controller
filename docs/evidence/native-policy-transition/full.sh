#!/bin/bash
set -euo pipefail
out=/private/tmp/cmtc-native-policy-transition-20261025
rootful=(podman --url ssh://olasumbo@127.0.0.1:49691/tmp/cmtc-observer-rootful/podman.sock --identity /Users/olasumbo/.colima/_lima/_config/user)
podman --connection cmtc-ubuntu-build save --format docker-archive -o "$out/etcd-arm64.tar" 43e1e8d08cbb > "$out/etcd-export.log" 2>&1
"${rootful[@]}" load -i "$out/etcd-arm64.tar" > "$out/etcd-import.log" 2>&1
etcd_image=$(podman --connection cmtc-ubuntu-build image inspect --format '{{.Id}}' 43e1e8d08cbb)
"${rootful[@]}" image inspect "$etcd_image" > "$out/etcd-image.json"
task_etcd_id=$("${rootful[@]}" run -d --platform linux/arm64 --cpus 0.5 --memory 256m --pids-limit 256 --name cmtc-native-transition-etcd-20261025 --entrypoint /usr/local/bin/etcd "$etcd_image" --name default --data-dir /tmp/cmtc-etcd --listen-client-urls http://127.0.0.1:4002 --advertise-client-urls http://127.0.0.1:4002 --listen-peer-urls http://127.0.0.1:4003 --initial-advertise-peer-urls http://127.0.0.1:4003 --initial-cluster default=http://127.0.0.1:4003)
printf '%s\n' "$task_etcd_id" > "$out/etcd-container-id"
cleanup() {
 "${rootful[@]}" logs "$task_etcd_id" > "$out/etcd-runtime-fourth.log" 2>&1 || true
 "${rootful[@]}" inspect "$task_etcd_id" > "$out/etcd-container-final-fourth.json" || true
 "${rootful[@]}" rm -f "$task_etcd_id" > "$out/etcd-cleanup-fourth.log"
}
trap cleanup EXIT
"${rootful[@]}" run --rm --platform linux/arm64 --privileged --network container:"$task_etcd_id" --cpus 2 --memory 4g --security-opt label=disable -e INTEGRATION_TESTS=1 -e PRIVILEGED_TESTS=1 -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src f0093acd3f0ab3a1966ebe348eaa3c78ac706f94839f52209ae7120508cf2529 sh -ec 'mount --make-rprivate /; mkdir -p /sys/fs/bpf; mount -t bpf bpffs /sys/fs/bpf; gofmt -w pkg/endpoint/*policy*transition*.go pkg/endpoint/policy_authority_test.go pkg/policy/ztunnel_policy_transition*.go pkg/ztunnel/admission/policy*.go pkg/ztunnel/zds/policy*.go; go test -race -count=1 -json ./pkg/policy ./pkg/endpoint ./pkg/endpointmanager ./pkg/ztunnel/admission ./pkg/ztunnel/zds; go vet ./pkg/policy ./pkg/endpoint ./pkg/endpointmanager ./pkg/ztunnel/admission ./pkg/ztunnel/zds' > "$out/full-fourth.jsonl" 2>&1
