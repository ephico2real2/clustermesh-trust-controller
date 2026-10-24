#!/usr/bin/env bash
set -euo pipefail
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
cd /private/tmp/cmtc-spire-workload-qualification
backend=$(kubectl -n mtls-spike get pods -l app=mtls-server -o jsonpath='{.items[0].status.podIP}')
for stream in service pod; do
 target=http://server.mtls-spike/
 [ "$stream" != pod ] || target="http://$backend/"
 kubectl -n mtls-spike apply -f - <<YAML
apiVersion: batch/v1
kind: Job
metadata: {name: mtls-capture-$stream}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 400
  template:
    metadata: {labels: {app: mtls-load}}
    spec:
      nodeSelector: {kubernetes.io/hostname: cmtc-mtls-worker}
      serviceAccountName: client
      automountServiceAccountToken: false
      restartPolicy: Never
      securityContext: {runAsNonRoot: true, runAsUser: 65532, fsGroup: 65532}
      volumes: [{name: results, emptyDir: {}}]
      initContainers:
        - name: fortio
          image: fortio/fortio:1.75.3
          args: [load, '-qps', '10', '-c', '2', '-t', 300s, '-keepalive=false', '-nocatchup', '-uniform', '-json', /results/fortio.json, '$target']
          volumeMounts: [{name: results, mountPath: /results}]
          resources: {requests: {cpu: 25m, memory: 32Mi}, limits: {memory: 128Mi}}
      containers:
        - name: results
          image: alpine:3.20
          command: [cat, /results/fortio.json]
          volumeMounts: [{name: results, mountPath: /results, readOnly: true}]
          resources: {requests: {cpu: 10m, memory: 16Mi}, limits: {memory: 32Mi}}
YAML
done
for stream in service pod; do
 kubectl -n mtls-spike wait job/mtls-capture-$stream --for=condition=Complete --timeout=410s
 kubectl -n mtls-spike logs job/mtls-capture-$stream -c results > "artifacts/mtls-spike/mtls-capture-$stream.json"
 kubectl -n mtls-spike logs job/mtls-capture-$stream -c fortio > "artifacts/mtls-spike/mtls-capture-$stream.log"
done
python3 - <<'PY'
import json,pathlib
p=pathlib.Path('artifacts/mtls-spike');results=[]
for stream in ['service','pod']:
 j=json.loads((p/('mtls-capture-'+stream+'.json')).read_text())
 total=j['DurationHistogram']['Count'];success=j['RetCodes'].get('200',0)
 assert total>=2900 and success==total,(stream,total,j['RetCodes'])
 assert j['ActualDuration']>=295e9,(stream,j['ActualDuration'])
 results.append({'stream':stream,'requests':total,'http200':success,'durationSeconds':j['ActualDuration']/1e9,'actualQPS':j['ActualQPS']})
(p/'mtls-capture-summary.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results))
PY
