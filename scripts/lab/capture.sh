#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
out=${CMTC_CAPTURE_OUT:-artifacts/screenshots}
case "$out" in artifacts/*) ;; *) echo 'Capture output must be under artifacts/' >&2;exit 1;; esac
case "$out" in *..*) echo 'Capture output cannot traverse directories' >&2;exit 1;; esac
mkdir -p "$out"
capture_image=${CMTC_CAPTURE_IMAGE:-cmtc-capture:dev}
docker image inspect "$capture_image" >/dev/null
docker_args=(--rm --init --network host --shm-size=1g --env S=/captures --env CMTC_WALK_ENV_JSON --volume "$PWD/$out:/captures")
if [ -n "${CMTC_WALK_SPEC:-}" ]; then
  spec=$(realpath "$CMTC_WALK_SPEC")
  case "$spec" in *.yaml|*.yml) container_spec=/workspace/walk.yaml;; *) container_spec=/workspace/walk.json;; esac
  docker run "${docker_args[@]}" --volume "$spec:$container_spec:ro" --entrypoint node "$capture_image" /opt/cmtc-capture/walk.cjs "$container_spec"
  exit $?
fi
# Default CMTC walk: port-forward the actual Grafana and imported app.
kubectl --context kind-cmtc-a get namespace monitoring >/dev/null
kubectl --context kind-cmtc-a -n monitoring port-forward svc/grafana 3000:3000 > artifacts/grafana-forward.log 2>&1 &
grafana_pid=$!
kubectl --context kind-cmtc-b -n mesh-example port-forward svc/rebel-base 18080:80 > artifacts/application-forward.log 2>&1 &
app_pid=$!
trap 'kill "$grafana_pid" "$app_pid" 2>/dev/null || true' EXIT
ready=0
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:3000/api/health >/dev/null; then ready=1;break;fi
  sleep 2
done
[ "$ready" = 1 ] || { echo 'Grafana unavailable for screenshots' >&2;exit 1; }
# The walker judges app availability per page, so an app failure still leaves
# the dashboard captures and evidence available for publication.
# Only capture output is mounted; kubeconfigs and signing files stay on the runner.
docker run "${docker_args[@]}" "$capture_image"
