#!/usr/bin/env bash
# A local image registry for the kind labs and CI, so clusters pull images by digest instead of having them
# side-loaded (kind load). This is kind's documented pattern: https://kind.sigs.k8s.io/docs/user/local-registry/
# Published images still come from GHCR; this registry is only for images built on this machine.
#
#   local-registry.sh start               run the registry on 127.0.0.1:5001 (a no-op when it already runs)
#   local-registry.sh nodes CLUSTER       let every node of a kind cluster pull from localhost:5001
#   local-registry.sh push IMAGE NAME     push a local IMAGE as localhost:5001/NAME and print NAME's digest reference
set -euo pipefail
name=kind-registry
port=5001
# registry:3.1.1 (Docker Hub, 2026-09-21), pinned by its multi-platform index digest.
image=registry@sha256:325b4b29b041e82803abeb703e201655e4e23ab83264ec1a7c9ddb0a5b14a6e0

start() {
  case "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" in
    true) ;;
    false) docker start "$name" >/dev/null ;;
    *) docker run -d --restart=always -p "127.0.0.1:$port:5000" --network bridge --name "$name" "$image" >/dev/null ;;
  esac
}

nodes() {
  local cluster=$1 node
  # Inside a node, localhost is the node itself, so containerd is told that localhost:5001 means this registry.
  # kind node images from v0.27 read registry settings from /etc/containerd/certs.d without a config patch.
  for node in $(kind get nodes --name "$cluster"); do
    docker exec "$node" mkdir -p "/etc/containerd/certs.d/localhost:$port"
    printf '[host."http://%s:5000"]\n' "$name" | docker exec -i "$node" cp /dev/stdin "/etc/containerd/certs.d/localhost:$port/hosts.toml"
  done
  # The nodes reach the registry by name on kind's Docker network.
  if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$name")" = null ]; then
    docker network connect kind "$name"
  fi
}

push() {
  local source=$1 target="localhost:$port/$2:local"
  docker tag "$source" "$target"
  docker push "$target" >/dev/null
  # The digest the registry stored, which is what the cluster pulls.
  docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$target" | grep "^localhost:$port/$2@sha256:"
}

case "${1:-}" in
  start) start ;;
  nodes) nodes "${2:?usage: local-registry.sh nodes CLUSTER}" ;;
  push) push "${2:?usage: local-registry.sh push IMAGE NAME}" "${3:?usage: local-registry.sh push IMAGE NAME}" ;;
  *) sed -n '2,8p' "$0" >&2; exit 2 ;;
esac
