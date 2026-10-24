#!/usr/bin/env bash
set -euo pipefail
out=/private/tmp/cmtc-rebuild-20261024
name=cmtc-watch-session-etcd
podman --connection cmtc-ubuntu-build run -d --name "$name" --platform linux/arm64 --memory 512m --cpus 1 gcr.io/etcd-development/etcd:v3.7.2@sha256:7c6c239825d00e3f6328a69caafd54be92063acf0c2ce78b8394699f52b75dc3 etcd --name cmtc-watch-session --listen-client-urls http://127.0.0.1:4002 --advertise-client-urls http://127.0.0.1:4002 --listen-peer-urls http://127.0.0.1:2380 > "$out/watch-session-etcd-start-final.log" 2>&1
cleanup() {
 podman --connection cmtc-ubuntu-build logs "$name" > "$out/watch-session-etcd-final.log" 2>&1
 podman --connection cmtc-ubuntu-build rm -f "$name" > "$out/watch-session-etcd-cleanup.log" 2>&1
}
trap cleanup EXIT
podman --connection cmtc-ubuntu-build run --rm --network "container:$name" --platform linux/arm64 --cpus 2 --memory 4g --security-opt label=disable -e INTEGRATION_TESTS=1 -e GOMAXPROCS=2 -e GOMEMLIMIT=2GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src localhost/cmtc-cilium-test:local sh -ec 'go test -race -count=1 -v ./pkg/kvstore/store; go vet ./pkg/kvstore/store' > "$out/watch-session-final.log" 2>&1
printf '0\n' > "$out/watch-session-final.exit"
podman --connection cmtc-ubuntu-build run --rm --platform linux/arm64 --cpus 2 --memory 6g --security-opt label=disable -e GOMAXPROCS=2 -e GOMEMLIMIT=4GiB -e GOFLAGS=-p=2 -e GOCACHE=/cache -v /private/tmp/cilium-ztunnel-authorization-runtime:/src -v /private/tmp/cilium-ztunnel-linux-go-cache:/cache -w /src docker.io/golangci/golangci-lint@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481 golangci-lint run ./pkg/kvstore/store > "$out/watch-session-lint-final.log" 2>&1
printf '0\n' > "$out/watch-session-lint-final.exit"
