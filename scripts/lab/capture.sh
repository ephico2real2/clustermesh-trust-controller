#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p artifacts
capture_image=${CMTC_CAPTURE_IMAGE:-cmtc-capture:dev}
docker image inspect "$capture_image" >/dev/null
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
# Linux host networking reaches the runner's loopback-only kubectl forwards.
# Mount only evidence output; kubeconfigs and signing files stay on the runner.
docker run --rm --init --network host --shm-size=1g \
  --volume "$PWD/artifacts:/workspace/artifacts" "$capture_image"
