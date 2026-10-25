#!/usr/bin/env bash
# Bounded real traffic stays active while Grafana and application screenshots are captured.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p artifacts/load

streams=(
  cmtc-a-shop cmtc-b-shop
  cmtc-a-mesh-80 cmtc-a-mesh-8080 cmtc-a-mesh-31337
  cmtc-b-mesh-80 cmtc-b-mesh-8080 cmtc-b-mesh-31337
)

run_id=${CMTC_LOAD_RUN_ID:-}
if [[ "${1:-}" == start ]]; then
  run_id=${run_id:-$(date -u +%y%m%d%H%M%S)}
  [[ "$run_id" =~ ^[a-z0-9-]+$ ]] || { echo "invalid CMTC_LOAD_RUN_ID: $run_id" >&2; exit 2; }
  run_dir="artifacts/load/$run_id"
  [ ! -e "$run_dir" ] || { echo "Refusing to overwrite load evidence: $run_dir" >&2; exit 1; }
  mkdir "$run_dir"
  printf '%s\n' "$run_id" > artifacts/load/current-run
else
  run_id=${run_id:-$(cat artifacts/load/current-run)}
  [[ "$run_id" =~ ^[a-z0-9-]+$ ]] || { echo "invalid load run id: $run_id" >&2; exit 2; }
  run_dir="artifacts/load/$run_id"
fi

job_name() { printf 'cmtc-load-%s-%s' "$run_id" "$1"; }

case "${1:-}" in
start)
  for stream in "${streams[@]}"; do
    case "$stream" in
      cmtc-a-shop) cluster=cmtc-a; target=http://shop.cf2cnp-lab/; ns=cf2cnp-lab; qps=20 ;;
      cmtc-b-shop) cluster=cmtc-b; target=http://shop.cf2cnp-lab/; ns=cf2cnp-lab; qps=20 ;;
      cmtc-a-mesh-80) cluster=cmtc-a; target=http://rebel-base-cmtc-b.mesh-example:80/; ns=mesh-example; qps=10 ;;
      cmtc-a-mesh-8080) cluster=cmtc-a; target=http://rebel-base-cmtc-b.mesh-example:8080/; ns=mesh-example; qps=5 ;;
      cmtc-a-mesh-31337) cluster=cmtc-a; target=http://rebel-base-cmtc-b.mesh-example:31337/; ns=mesh-example; qps=5 ;;
      cmtc-b-mesh-80) cluster=cmtc-b; target=http://rebel-base-cmtc-a.mesh-example:80/; ns=mesh-example; qps=10 ;;
      cmtc-b-mesh-8080) cluster=cmtc-b; target=http://rebel-base-cmtc-a.mesh-example:8080/; ns=mesh-example; qps=5 ;;
      cmtc-b-mesh-31337) cluster=cmtc-b; target=http://rebel-base-cmtc-a.mesh-example:31337/; ns=mesh-example; qps=5 ;;
    esac
    job=$(job_name "$stream")
    kubectl --context "kind-$cluster" -n "$ns" create -f - -o json > "$run_dir/$stream.job-created.json" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: $job
  labels: {app.kubernetes.io/name: cmtc-load, cmtc.io/load-run: "$run_id", cmtc.io/load-stream: "$stream"}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 480
  template:
    metadata:
      labels: {app: pos, app.kubernetes.io/name: cmtc-load, cmtc.io/load-run: "$run_id"}
    spec:
      restartPolicy: Never
      securityContext: {runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532}
      volumes: [{name: results, emptyDir: {}}]
      initContainers:
        - name: fortio
          image: fortio/fortio:1.75.3
          args: [load, '-qps', '$qps', '-c', '2', '-t', 6m, '-nocatchup', '-uniform', '-json', /results/fortio.json, '$target']
          volumeMounts: [{name: results, mountPath: /results}]
          resources:
            requests: {cpu: 25m, memory: 32Mi}
            limits: {memory: 128Mi}
      containers:
        - name: results
          image: alpine:3.20
          command: [cat, /results/fortio.json]
          volumeMounts: [{name: results, mountPath: /results, readOnly: true}]
          resources:
            requests: {cpu: 10m, memory: 16Mi}
            limits: {memory: 32Mi}
EOF
    printf '%s\t%s\t%s\t%s\n' "$stream" "$cluster" "$ns" "$target" >> "$run_dir/streams.tsv"
    echo "Created $stream: $target (job=$job, qps=$qps, run=$run_id)"
  done
  # Create all streams before waiting. Image pulls must not consume the first
  # stream's six-minute load while later Jobs have not even been submitted.
  while IFS=$'\t' read -r stream cluster ns target; do
    job=$(job_name "$stream")
    pod=''
    for _ in $(seq 1 30); do
      pod=$(kubectl --context "kind-$cluster" -n "$ns" get pods -l "job-name=$job" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
      [ -z "$pod" ] || break
      sleep 1
    done
    [ -n "$pod" ] || { echo "load pod was not created: $stream ($job)" >&2; exit 1; }
    kubectl --context "kind-$cluster" -n "$ns" wait "pod/$pod" --for=jsonpath='{.status.initContainerStatuses[0].state.running.startedAt}' --timeout=3m
    expected_uid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["uid"])' "$run_dir/$stream.job-created.json")
    actual_uid=$(kubectl --context "kind-$cluster" -n "$ns" get "job/$job" -o jsonpath='{.metadata.uid}')
    [ "$expected_uid" = "$actual_uid" ] || { echo "Load Job was replaced: $stream" >&2; exit 1; }
    echo "Running $stream: $target (job=$job, run=$run_id)"
  done < "$run_dir/streams.tsv"
  ;;
collect)
  frozen_manifest=${CMTC_LOAD_MANIFEST:-$run_dir/load-manifest.json}
  if [ -z "${CMTC_LOAD_MANIFEST:-}" ] && [ ! -e "$frozen_manifest" ]; then
    frozen_manifest="${CMTC_CAPTURE_OUT:-artifacts/screenshots}/load-manifest.json"
  fi
  if [ -n "${CMTC_LOAD_MANIFEST:-}" ] || [ -e "$frozen_manifest" ]; then
    python3 scripts/capture/collect_frozen_load.py --run-dir "$run_dir" --manifest "$frozen_manifest"
  else
    for stream in "${streams[@]}"; do
      case "$stream" in
        cmtc-a-shop|cmtc-a-mesh-*) cluster=cmtc-a ;;
        cmtc-b-shop|cmtc-b-mesh-*) cluster=cmtc-b ;;
      esac
      case "$stream" in
        *-shop) ns=cf2cnp-lab; qps=20 ;;
        *-mesh-80) ns=mesh-example; qps=10 ;;
        *) ns=mesh-example; qps=5 ;;
      esac
      job=$(job_name "$stream")
      kubectl --context "kind-$cluster" -n "$ns" wait "job/$job" --for=condition=Complete --timeout=7m
      expected_uid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["metadata"]["uid"])' "$run_dir/$stream.job-created.json")
      actual_uid=$(kubectl --context "kind-$cluster" -n "$ns" get "job/$job" -o jsonpath='{.metadata.uid}')
      [ "$expected_uid" = "$actual_uid" ] || { echo "Load Job was replaced before collection: $stream" >&2; exit 1; }
      kubectl --context "kind-$cluster" -n "$ns" logs "job/$job" -c fortio > "$run_dir/$stream.log"
      kubectl --context "kind-$cluster" -n "$ns" logs "job/$job" -c results > "$run_dir/$stream.json"
    done
  fi
  python3 - "$run_dir" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
streams = {
    'cmtc-a-shop': 20, 'cmtc-b-shop': 20,
    'cmtc-a-mesh-80': 10, 'cmtc-b-mesh-80': 10,
    'cmtc-a-mesh-8080': 5, 'cmtc-b-mesh-8080': 5,
    'cmtc-a-mesh-31337': 5, 'cmtc-b-mesh-31337': 5,
}
results = []
for stream, qps in streams.items():
    data = json.loads((run_dir / f'{stream}.json').read_text())
    total = data['DurationHistogram']['Count']
    codes = data['RetCodes']
    success = codes.get('200', 0)
    assert total > qps * 120 and success / total >= 0.99, (stream, total, codes)
    assert data['ActualDuration'] >= 120 * 1e9 and data['ActualQPS'] >= qps / 2, (stream, data['ActualQPS'])
    (run_dir / f'{stream}.json').write_text(json.dumps(data, indent=2) + '\n')
    results.append({
        'stream': stream,
        'requests': total,
        'http200': success,
        'actualQPS': data['ActualQPS'],
        'durationSeconds': data['ActualDuration'] / 1e9,
    })
(run_dir / 'load-results.json').write_text(json.dumps(results, indent=2) + '\n')
pathlib.Path('artifacts/load-results.json').write_text(json.dumps(results, indent=2) + '\n')
print(f'PASS: measured eight unique local and cross-cluster streams; evidence={run_dir}')
PY
  ;;
*) echo 'expected start or collect' >&2; exit 2 ;;
esac
