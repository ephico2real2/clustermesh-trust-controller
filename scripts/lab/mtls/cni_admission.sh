#!/usr/bin/env bash
set -euo pipefail
export PATH="/private/tmp/cmtc-mac-qualification/.tmp/bin:$PATH"
export KUBECONFIG=/home/olasumbo.guest/.kube/cmtc-mtls-spike
worker=cmtc-mtls-worker
expected_source="${CMTC_CNI_AGENT_SOURCE:?set exact candidate agent source}"
[[ "$expected_source" =~ ^[0-9a-f]{40}$ ]]
run="$(date -u +%Y%m%d%H%M%S)-$$"
namespace="cmtc-cni-$run"
output_root="${CMTC_CNI_OUTPUT_ROOT:?set an absolute task-owned evidence directory}"
[[ "$output_root" = /* ]]
out="$output_root/cni-fixture-$run"
marker="/tmp/cmtc-cni-$run"
mkdir -p "$out"
test "$(kubectl config current-context)" = kind-cmtc-mtls
docker inspect "$worker" >/dev/null
kubectl -n kube-system get ds ztunnel-cilium -o json >"$out/proxy-ds.json"
kubectl -n kube-system get pods -l app=ztunnel-cilium -o json >"$out/proxies-before.json"
kubectl -n kube-system get pods -l k8s-app=cilium -o json >"$out/agents-before.json"

readarray -t target < <(python3 - "$out/proxies-before.json" "$out/agents-before.json" "$worker" <<'PY'
import json,sys
proxies=json.load(open(sys.argv[1]))['items']; agents=json.load(open(sys.argv[2]))['items']; node=sys.argv[3]
pods=[p for p in proxies if p['spec']['nodeName']==node]
assert len(pods)==1, 'expected exactly one worker ztunnel'
p=pods[0]; statuses=[x for x in p['status']['containerStatuses'] if x['name']=='istio-proxy']
assert len(statuses)==1 and statuses[0]['ready'], 'worker proxy must start ready'
s=statuses[0]; cid=s['containerID']; assert cid.startswith('containerd://')
assert 'livenessProbe' not in next(c for c in p['spec']['containers'] if c['name']=='istio-proxy'), 'review liveness behavior before pausing'
a=[p for p in agents if p['spec']['nodeName']==node]; assert len(a)==1
print(p['metadata']['name']);print(p['metadata']['uid']);print(cid.split('://',1)[1]);print(s['restartCount']);print(a[0]['metadata']['name'])
PY
)
test "${#target[@]}" -eq 5
proxy=${target[0]}; proxy_uid=${target[1]}; cid=${target[2]}; restarts=${target[3]}; agent=${target[4]}
[[ "$cid" =~ ^[0-9a-f]{64}$ ]]
kubectl -n kube-system exec "$agent" -c cilium-agent -- cilium-agent --version >"$out/agent-version.txt"
grep -F "${expected_source:0:10}" "$out/agent-version.txt"
printf "%s\n" "$expected_source" >"$out/expected-source.txt"
docker exec "$worker" ctr -n k8s.io tasks ls >"$out/tasks-before.txt"
docker exec "$worker" ctr -n k8s.io tasks ls | awk -v id="$cid" '$1==id && $3=="RUNNING" {found=1} END {exit !found}'
image=$(kubectl -n mtls-spike get pod client -o jsonpath='{.spec.containers[0].image}')
test -n "$image"
# Existing client image supplies sh, date, sleep and wget. Fetch/cache before fault.
kubectl -n mtls-spike exec client -- sh -c 'command -v sh; command -v date; command -v sleep; command -v wget' >"$out/app-tools.txt"
docker exec "$worker" crictl --runtime-endpoint unix:///run/containerd/containerd.sock pull "$image" >"$out/prepull.log" 2>&1
docker exec "$worker" mkdir -p "$marker"
kubectl create namespace "$namespace"
kubectl label namespace "$namespace" io.cilium/mtls-enabled=true
kubectl -n "$namespace" create serviceaccount app
kubectl get namespace "$namespace" -o json >"$out/namespace-before.json"
since=$(date -u +%Y-%m-%dT%H:%M:%SZ)
paused=0; watchdog=
cleanup() {
  command_rc=$?
  trap - EXIT INT TERM
  if ((paused)); then docker exec "$worker" ctr -n k8s.io tasks resume "$cid" >>"$out/resume-cleanup.log" 2>&1 || true; fi
  if [[ -n "$watchdog" ]]; then kill "$watchdog" 2>/dev/null || true; fi
  kubectl -n "$namespace" get pod app -o json >"$out/pod-final.json" 2>/dev/null || true
  kubectl -n "$namespace" get events -o json >"$out/events-final.json" 2>/dev/null || true
  kubectl -n kube-system logs "$agent" --since-time="$since" --timestamps >"$out/agent.log" 2>&1 || true
  kubectl -n kube-system logs "$proxy" --since-time="$since" --timestamps >"$out/proxy.log" 2>&1 || true
  kubectl delete namespace "$namespace" --wait=false >>"$out/cleanup.log" 2>&1 || true
  # Keep the unique marker as evidence; do not prune worker /tmp or other jobs.
  exit "$command_rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
docker exec "$worker" ctr -n k8s.io tasks pause "$cid"
paused=1
( sleep 100; docker exec "$worker" ctr -n k8s.io tasks resume "$cid" >>"$out/watchdog-resume.log" 2>&1 || true ) &
watchdog=$!
python3 - "$namespace" "$worker" "$image" "$marker" >"$out/pod.json" <<'PY'
import json,sys
ns,node,image,marker=sys.argv[1:]
print(json.dumps({'apiVersion':'v1','kind':'Pod','metadata':{'name':'app','namespace':ns,'labels':{'app':'ztunnel-cilium','cmtc-test':'cni-admission'}},'spec':{'nodeName':node,'serviceAccountName':'app','restartPolicy':'Never','containers':[{'name':'app','image':image,'imagePullPolicy':'IfNotPresent','command':['sh','-c','printf "STARTED uid=%s at=%s\\n" "$POD_UID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > /evidence/started; cat /evidence/started; while :; do sleep 1; done'],'env':[{'name':'POD_UID','valueFrom':{'fieldRef':{'fieldPath':'metadata.uid'}}}],'volumeMounts':[{'name':'evidence','mountPath':'/evidence'}]}],'volumes':[{'name':'evidence','hostPath':{'path':marker,'type':'Directory'}}]}}))
PY
kubectl apply -f "$out/pod.json"
pod_uid=$(kubectl -n "$namespace" get pod app -o jsonpath='{.metadata.uid}')
printf '%s\n' "$pod_uid" >"$out/pod-uid.txt"
hold_end=$((SECONDS + 75))
sample=0
while ((SECONDS < hold_end)); do
  sample=$((sample + 1))
  kubectl -n "$namespace" get pod app -o json >"$out/hold-pod-$sample.json"
  kubectl -n kube-system get pod "$proxy" -o json >"$out/hold-proxy-$sample.json"
  docker exec "$worker" crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps -a -o json >"$out/hold-cri-$sample.json"
  docker exec "$worker" ctr -n k8s.io tasks ls >"$out/hold-tasks-$sample.txt"
  docker exec "$worker" test ! -e "$marker/started"
  python3 - "$out" "$sample" "$pod_uid" "$proxy_uid" "$cid" "$restarts" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); s,uid,proxy_uid,cid,restarts=sys.argv[2:]
pod=json.load(open(p/f'hold-pod-{s}.json')); proxy=json.load(open(p/f'hold-proxy-{s}.json')); cri=json.load(open(p/f'hold-cri-{s}.json'))
assert pod['metadata']['uid']==uid
for status in pod.get('status',{}).get('containerStatuses',[]):
    assert not status.get('containerID') and not status.get('state',{}).get('running') and not status.get('lastState',{}).get('terminated'), 'application container existed before ACK'
assert not [c for c in cri.get('containers',[]) if c.get('labels',{}).get('io.kubernetes.pod.uid')==uid], 'CRI application container existed before ACK'
assert proxy['metadata']['uid']==proxy_uid, 'paused Pod was replaced; test invalid'
status=next(c for c in proxy['status']['containerStatuses'] if c['name']=='istio-proxy')
assert status['containerID']=='containerd://'+cid and status['restartCount']==int(restarts), 'paused container changed; test invalid'
tasks=[line.split() for line in (p/f'hold-tasks-{s}.txt').read_text().splitlines()]
assert any(len(row)>=3 and row[0]==cid and row[2]=='PAUSED' for row in tasks), 'proxy was not continuously paused'
PY
  sleep 1
done
kubectl -n "$namespace" get events -o json >"$out/hold-events.json"
python3 - "$out/hold-events.json" <<'PY'
import json,sys
events=json.load(open(sys.argv[1]))['items']
assert any('endpoint startup admission failed' in e.get('message','') for e in events), 'no real CNI admission failure observed; do not call Pending a pass'
PY
docker exec "$worker" ctr -n k8s.io tasks resume "$cid"
paused=0
kill "$watchdog" 2>/dev/null || true
watchdog=
kubectl -n kube-system wait "pod/$proxy" --for=condition=Ready --timeout=60s
kubectl -n "$namespace" wait pod/app --for=condition=Ready --timeout=120s
kubectl -n "$namespace" get pod app -o json >"$out/pod-recovered.json"
docker exec "$worker" cat "$marker/started" >"$out/started-marker.txt"
kubectl -n kube-system logs "$agent" --since-time="$since" --timestamps >"$out/agent-recovered.log"
python3 - "$out" "$pod_uid" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]); uid=sys.argv[2]
pod=json.load(open(p/'pod-recovered.json')); assert pod['metadata']['uid']==uid
assert uid in (p/'started-marker.txt').read_text()
lines=(p/'agent-recovered.log').read_text().splitlines()
acks=[line for line in lines if uid in line and 'Endpoint enrollment acknowledged' in line]
admissions=[line for line in lines if uid in line and 'Endpoint startup admission completed' in line]
assert acks and admissions, 'fresh matching ADD ACK and production admission-completion logs required'
(p/'ack-and-admission.log').write_text('\n'.join(acks+admissions)+'\n')
status=next(c for c in pod['status']['containerStatuses'] if c['name']=='app')
assert status.get('state',{}).get('running') and status.get('containerID')
(p/'application-container-id.txt').write_text(status['containerID']+'\n')
print('PASS paused: no marker, Pod app instance or CRI app container; recovery: matching ACK/admission and app start')
PY
app_cid=$(sed 's|^containerd://||' "$out/application-container-id.txt")
docker exec "$worker" crictl --runtime-endpoint unix:///run/containerd/containerd.sock inspect "$app_cid" | python3 -c 'import json,sys; s=json.load(sys.stdin)["status"]; print(json.dumps({k:s.get(k) for k in ["id","createdAt","startedAt","finishedAt","state","labels"]},indent=2))' >"$out/application-cri-timestamps.json"
python3 - "$out" <<'PY_CHECK'
import datetime,json,pathlib,re,sys
p=pathlib.Path(sys.argv[1])
def ns(stamp):
 m=re.fullmatch(r'(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?Z',stamp)
 assert m,stamp
 base=int(datetime.datetime.fromisoformat(m[1]+'+00:00').timestamp())
 return base*10**9+int((m[2] or '').ljust(9,'0')[:9])
lines=(p/'ack-and-admission.log').read_text().splitlines()
ack=max(ns(line.split()[0]) for line in lines if 'Endpoint enrollment acknowledged' in line)
admission=max(ns(line.split()[0]) for line in lines if 'Endpoint startup admission completed' in line)
cri=json.loads((p/'application-cri-timestamps.json').read_text())
started=ns(cri['startedAt']) if isinstance(cri['startedAt'],str) and 'T' in cri['startedAt'] else int(cri['startedAt'])
created=ns(cri['createdAt']) if isinstance(cri['createdAt'],str) and 'T' in cri['createdAt'] else int(cri['createdAt'])
assert ack<=admission<=created<=started,(ack,admission,created,started)
report={'test':'actual-cni-failure-recovery','source':(p/'expected-source.txt').read_text().strip(),'podUID':(p/'pod-uid.txt').read_text().strip(),'pausedApplicationContainers':0,'freshAckEpochNs':ack,'admissionEpochNs':admission,'applicationCreatedEpochNs':created,'applicationStartedEpochNs':started,'passed':True}
(p/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
PY_CHECK
echo "Evidence: $out"
