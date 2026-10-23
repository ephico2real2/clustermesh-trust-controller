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
      containers:
        - name: fortio
          image: fortio/fortio:1.75.3
          args: [load, '-qps', '$qps', '-c', '2', '-t', 6m, '-nocatchup', '-uniform', '-json', /dev/stdout, '$target']
          resources:
            requests: {cpu: 25m, memory: 32Mi}
            limits: {memory: 128Mi}
EOF
    kubectl --context "kind-$cluster" -n "$ns" wait pod -l job-name=cmtc-load --for=condition=Ready --timeout=3m
  done
  ;;
collect)
  for stream in cmtc-a-shop cmtc-b-shop cmtc-a-mesh; do
    cluster=${stream%-*}; ns=cf2cnp-lab
    [ "$stream" != cmtc-a-mesh ] || ns=mesh-example
    kubectl --context "kind-$cluster" -n "$ns" wait job/cmtc-load --for=condition=Complete --timeout=7m
    kubectl --context "kind-$cluster" -n "$ns" logs job/cmtc-load > "artifacts/load/$stream.log"
  done
  python3 - <<'PY'
import json,pathlib,re
results=[]
for stream,qps in [('cmtc-a-shop',20),('cmtc-b-shop',20),('cmtc-a-mesh',10)]:
    text=pathlib.Path('artifacts/load/'+stream+'.log').read_text()
    # Fortio writes progress before its JSON summary; tolerate trailing log text.
    data=None
    for match in re.finditer(r'\{',text):
        try: candidate,_=json.JSONDecoder().raw_decode(text[match.start():])
        except json.JSONDecodeError: continue
        if isinstance(candidate,dict) and 'RetCodes' in candidate and 'DurationHistogram' in candidate:
            data=candidate;break
    assert data is not None,(stream,'missing Fortio summary')
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
