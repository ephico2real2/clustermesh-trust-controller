#!/usr/bin/env bash
# Checks every rule file and runs every promtool unit test under rules/.
#
# promtool is the one of Prometheus 3.7.0, the version both lab Prometheus servers run
# (docker.io/prom/prometheus@sha256:29c1e0b4..., read from the Pod status on 2026-10-27). Pinning the
# digest keeps a Prometheus release from failing, or passing, a change that did not touch the rules.
# quay.io serves the same manifest digest as Docker Hub for v3.7.0. The container never pulls and has
# no network; PROMTOOL names a local promtool binary instead, for example the 3.7.0 release archive.
#
# Usage: rules/run-promtool.sh            check and test everything with the pinned image
#        PROMTOOL=/path/to/promtool rules/run-promtool.sh
#        PODMAN_CONNECTION=podman-machine-default rules/run-promtool.sh
# Needs podman or docker (CONTAINER_ENGINE picks one) when PROMTOOL is unset. PODMAN_CONNECTION
# names the podman connection to use instead of the default one.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="quay.io/prometheus/prometheus:v3.7.0@sha256:29c1e0b48ad816750245dea3d65ac3ce57dda30547e67b1e9a5176e2953cc4dc"

promtool() {
  if [[ -n "${PROMTOOL:-}" ]]; then
    "${PROMTOOL}" "$@"
    return
  fi
  local engine="${CONTAINER_ENGINE:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
  local connection=()
  if [[ "${engine}" == podman && -n "${PODMAN_CONNECTION:-}" ]]; then
    connection=(--connection "${PODMAN_CONNECTION}")
  fi
  # ${a[@]+"${a[@]}"}: an empty array under set -u on bash 3.2 (macOS /bin/bash).
  "${engine}" ${connection[@]+"${connection[@]}"} run --rm --pull=never --network none -v "${PWD}:/w:ro" --workdir /w \
    --entrypoint promtool "${IMAGE}" "$@"
}

rule_files=(*.rules.yaml proposed/*.rules.yaml)
test_files=(tests/*.test.yaml)

promtool --version 2>&1 | head -1
promtool check rules "${rule_files[@]}"
promtool test rules "${test_files[@]}"
