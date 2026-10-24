#!/usr/bin/env bash
# Bounded real traffic stays active while Grafana and application PNGs are captured.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p artifacts/load
case "${1:-}" in
start)
  for stream in cmtc-a-shop cmtc-b-shop cmtc-a-mesh; do
    cluster=${stream%-*}; target=http://shop.cf2cnp-lab/; ns=cf2cnp-lab; qps=20
    if [ "$stream" = cmtc-a-mesh ]; then target=http://rebel-base.mesh-example/; ns=mesh-example; qps=10; fi
    kubectl --context "kind-$cluster" -n "$ns" apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata: {name: cmtc-load}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 480
  template:
    metadata:
      labels: {app: pos, app.kubernetes.io/name: cmtc-load}
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
    pod=''
    for _ in $(seq 1 30); do
      pod=$(kubectl --context "kind-$cluster" -n "$ns" get pods -l job-name=cmtc-load -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
      [ -z "$pod" ] || break
      sleep 1
    done
    [ -n "$pod" ] || { echo "Load pod was not created: $stream" >&2; exit 1; }
    kubectl --context "kind-$cluster" -n "$ns" wait "pod/$pod" --for=jsonpath='{.status.initContainerStatuses[0].state.running.startedAt}' --timeout=3m
  done
  ;;
collect)
  for stream in cmtc-a-shop cmtc-b-shop cmtc-a-mesh; do
    cluster=${stream%-*}; ns=cf2cnp-lab
    [ "$stream" != cmtc-a-mesh ] || ns=mesh-example
    kubectl --context "kind-$cluster" -n "$ns" wait job/cmtc-load --for=condition=Complete --timeout=7m
    kubectl --context "kind-$cluster" -n "$ns" logs job/cmtc-load -c fortio > "artifacts/load/$stream.log"
    kubectl --context "kind-$cluster" -n "$ns" logs job/cmtc-load -c results > "artifacts/load/$stream.json"
  done
  python3 - <<'PY'
import json,pathlib
results=[]
for stream,qps in [('cmtc-a-shop',20),('cmtc-b-shop',20),('cmtc-a-mesh',10)]:
    data=json.loads(pathlib.Path('artifacts/load/'+stream+'.json').read_text())
    total=data['DurationHistogram']['Count'];codes=data['RetCodes'];success=codes.get('200',0)
    assert total>qps*120 and success/total>=0.99,(stream,total,codes)
    assert data['ActualDuration']>=120*1e9 and data['ActualQPS']>=qps/2,(stream,data['ActualQPS'])
    pathlib.Path('artifacts/load/'+stream+'.json').write_text(json.dumps(data,indent=2)+'\n')
    results.append({'stream':stream,'requests':total,'http200':success,'actualQPS':data['ActualQPS'],'durationSeconds':data['ActualDuration']/1e9})
pathlib.Path('artifacts/load-results.json').write_text(json.dumps(results,indent=2)+'\n')
print('PASS: measured successful local policy and cross-cluster traffic through published fork images')
PY
  ;;
*) echo 'expected start or collect' >&2; exit 2;;
esac
