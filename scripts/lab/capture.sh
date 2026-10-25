#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${CMTC_CAPTURE_OUT:-artifacts/screenshots}
case "$out" in artifacts/*) ;; *) echo 'Capture output must be under artifacts/' >&2;exit 1;; esac
case "$out" in *..*) echo 'Capture output cannot traverse directories' >&2;exit 1;; esac
mkdir -p "$out"
capture_image=${CMTC_CAPTURE_IMAGE:-cmtc-capture:dev}
app_forward_port=${CMTC_APP_FORWARD_PORT:-28080}
app_url=${CMTC_APP_URL:-http://127.0.0.1:$app_forward_port}
engine=(docker)
if [ "${CMTC_CAPTURE_ENGINE:-docker}" = podman ]; then
  engine=(podman --connection "${CMTC_PODMAN_CONNECTION:-cmtc-ubuntu-build}")
elif [ "${CMTC_CAPTURE_ENGINE:-docker}" != docker ]; then
  echo 'Expected docker or podman capture engine' >&2; exit 2
fi
"${engine[@]}" image inspect "$capture_image" >/dev/null
docker_args=(--rm --init --network host --shm-size=1g --env S=/captures --env CMTC_WALK_ENV_JSON --env CMTC_REQUIRE_NATIVE_MTLS --env CMTC_REQUIRE_ISSUER_PROFILE --env CMTC_REQUIRE_FENCE --env CMTC_REQUIRE_OBSERVER --env CMTC_CAPTURE_FROM_MS --env CMTC_CAPTURE_TO_MS --env CMTC_CAPTURE_DEADLINE_MS --env CMTC_GRAFANA_URL --volume "$PWD/$out:/captures")
docker_args+=(--env "CMTC_APP_URL=$app_url")
capture_run=${CMTC_CAPTURE_RUN_ID:-$$}
cidfile="$PWD/$out/container.cid"
[ ! -e "$cidfile" ] || { echo 'Capture output already has a container record' >&2; exit 1; }
docker_args+=(--cidfile "$cidfile" --label "security.cmtc.io/capture-run=$capture_run")
grafana_pid=''
app_pid=''
cleanup() {
  rc=$?
  trap - EXIT TERM INT
  for pid in "$grafana_pid" "$app_pid"; do
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
    [ -z "$pid" ] || wait "$pid" 2>/dev/null || true
  done
  if [ -s "$cidfile" ]; then
    cid=$(cat "$cidfile")
    if [[ "$cid" =~ ^[0-9a-f]{64}$ ]]; then
      if label=$("${engine[@]}" inspect --format '{{ index .Config.Labels "security.cmtc.io/capture-run" }}' "$cid" 2>/dev/null); then
        if [ "$label" = "$capture_run" ]; then
          "${engine[@]}" rm -f "$cid" > "$out/container-cleanup.log" 2>&1 || rc=1
        else
          echo 'Refusing to remove a container with another capture owner' >&2
          rc=1
        fi
      else
        # --rm normally removed it. Require a successful exact-ID absence read.
        if remaining=$("${engine[@]}" ps -a --no-trunc --filter "id=$cid" --format '{{.ID}}' 2>/dev/null); then
          [ -z "$remaining" ] || rc=1
        else
          rc=1
        fi
      fi
    else
      echo 'Invalid capture container record' >&2
      rc=1
    fi
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
if [ -n "${CMTC_WALK_SPEC:-}" ]; then
  spec=$(realpath "$CMTC_WALK_SPEC")
  case "$spec" in *.yaml|*.yml) container_spec=/workspace/walk.yaml;; *) container_spec=/workspace/walk.json;; esac
  "${engine[@]}" run "${docker_args[@]}" --volume "$spec:$container_spec:ro" --entrypoint node "$capture_image" /opt/cmtc-capture/walk.cjs "$container_spec"
  exit $?
fi
# Local qualification can use paired loopback URLs forwarded into the Podman VM.
# CI uses its own bounded port forwards below. Never silently mix the two paths.
if [ -n "${CMTC_GRAFANA_URL:-}" ]; then
  [ -n "${CMTC_APP_URL:-}" ] || { echo 'Set both external capture URLs' >&2; exit 2; }
  "${engine[@]}" run "${docker_args[@]}" "$capture_image"
  exit $?
fi
# Default CMTC walk: port-forward the actual Grafana and imported app.
kubectl --context kind-cmtc-a get namespace monitoring >/dev/null
kubectl --context kind-cmtc-a -n monitoring port-forward svc/grafana 3000:3000 > artifacts/grafana-forward.log 2>&1 &
grafana_pid=$!
kubectl --context kind-cmtc-b -n mesh-example port-forward --address 127.0.0.1 svc/rebel-base-cmtc-b "$app_forward_port:80" > artifacts/application-forward.log 2>&1 &
app_pid=$!
ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$grafana_pid" 2>/dev/null; then cat artifacts/grafana-forward.log >&2; exit 1; fi
  if grep -Fq 'Forwarding from 127.0.0.1:3000 -> 3000' artifacts/grafana-forward.log && curl -fsS http://127.0.0.1:3000/api/health >/dev/null 2>&1; then ready=1;break;fi
  sleep 2
done
[ "$ready" = 1 ] || { echo 'Grafana unavailable for screenshots' >&2;exit 1; }
app_ready=0
for _ in $(seq 1 60); do
  if ! kill -0 "$app_pid" 2>/dev/null; then cat artifacts/application-forward.log >&2; exit 1; fi
  if grep -Fq "Forwarding from 127.0.0.1:$app_forward_port -> 80" artifacts/application-forward.log && curl -fsS --max-time 2 "$app_url/" 2>/dev/null | grep -Fq 'cmtc-b'; then app_ready=1; break; fi
  sleep 1
done
[ "$app_ready" = 1 ] || { cat artifacts/application-forward.log >&2; echo 'Global Service screenshot target did not return the cmtc-b backend' >&2;exit 1; }
# The walker judges app availability per page, so an app failure still leaves
# the dashboard captures and evidence available for publication.
# Only capture output is mounted; kubeconfigs and signing files stay on the runner.
"${engine[@]}" run "${docker_args[@]}" "$capture_image"
