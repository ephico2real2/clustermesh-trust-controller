#!/usr/bin/env bash
set -euo pipefail
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
cd /private/tmp/cmtc-spire-workload-qualification
out=artifacts/mtls-spike/authenticated-only-f052d127
kubectl -n kube-system logs deploy/cilium-operator > "$out/podman-operator-startup.log"
grep -Fq 'event=ack' "$out/podman-operator-startup.log"
restore(){ kubectl -n cilium-spire scale statefulset/spire-server --replicas=1 >/dev/null; }
trap restore EXIT
kubectl -n cilium-spire scale statefulset/spire-server --replicas=0
kubectl -n cilium-spire wait pod/spire-server-0 --for=delete --timeout=60s
kubectl -n kube-system rollout restart deployment/cilium-operator
kubectl -n kube-system rollout status deployment/cilium-operator --timeout=60s
sleep 12
kubectl -n kube-system logs deploy/cilium-operator > "$out/podman-operator-spire-unavailable.log"
grep -Fq 'event=retry' "$out/podman-operator-spire-unavailable.log"
if grep -Fq 'event=ack' "$out/podman-operator-spire-unavailable.log"; then
 echo 'FAIL: initialized while the SPIRE server was absent' >&2; exit 1
fi
restore
kubectl -n cilium-spire rollout status statefulset/spire-server --timeout=90s
for attempt in $(seq 1 45); do
 kubectl -n kube-system logs deploy/cilium-operator > "$out/podman-operator-spire-recovery.log"
 if grep -Fq 'event=ack' "$out/podman-operator-spire-recovery.log"; then break; fi
 sleep 2
done
grep -Fq 'event=ack' "$out/podman-operator-spire-recovery.log"
python3 - <<'PY'
from pathlib import Path
import json
p=Path('artifacts/mtls-spike/authenticated-only-f052d127')
before=(p/'podman-operator-spire-unavailable.log').read_text()
after=(p/'podman-operator-spire-recovery.log').read_text()
retries=[l for l in before.splitlines() if 'event=retry' in l]
acks=[l for l in after.splitlines() if 'event=ack' in l]
assert retries and acks
assert all(all(k in l for k in ['stage=server-ack','attempt=','elapsedDuration=','backOff=','deadline=','error=']) for l in retries)
result={'sourceSHA':'d8124529b590bfb24adbd3d2916a4a984b666f9e','retryEventsWhileUnavailable':len(retries),'ackWhileUnavailable':False,'ackAfterRecovery':True}
(p/'spire-retry-runtime-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
PY
