# Registrar current-image deployment audit

Proposal only. No product edits, compilation, Git writes or Kubernetes writes were performed by this auditor. Read-only API/exec metadata reads used explicit `kind-cmtc-a` / `kind-cmtc-b` contexts and `/private/tmp/cmtc-a-b-20261024.kubeconfig`. Root retains sole compiler/live-writer ownership. Apply **edit → run against cmtc-a/cmtc-b → test traffic, failures and recovery → package the verified change** to any implementation increment. Existing source is Opus-owned; this is an operational plan for already-built code.

## Findings that affect execution

1. `scripts/lab/spire/registrar_runtime_plan.py` does not exist. `test_registrar_runtime_plan.py` imports **`qualify_registrar.py`**. Reuse its pure `sidecar_template`, `canonical`, `sha`, `template_patch`, `wanted` and proof/readback functions. Do not run `Runner.execute()` to leave a permanent helper: it creates diagnostic fixtures and always removes its helper in `finally`.
2. Existing runner constants describe old registrar source `e39928bc4f79ad6da134e77583945c8e5e9d52bf` and old image config `1454f...`; they are deliberately unsuitable as proof of current `96cbc9e...`. Existing eighth-run report is qualified=true with cleanupErrors=[], but is historical proof only.
3. Current registrar image: `localhost/cmtc-spire-registrar@sha256:472a1164e46f570b87d15eff7272a4a48ede44e0a6720102395e4e73606a36fd`; config `dfdfda16f19d5301a0a90d840748f4c7076533b31a752eaf3fad9a21a8dad0d7`; Linux ARM64; source label `96cbc9eecaa95d830562c678f7e38041a17755a5`. Archive `/private/tmp/cmtc-primary-operations-20261025/registrar-96cbc9eeca.tar`.
4. **Both DaemonApproval images must be digest-qualified AND equal the actual Pod.Spec container image text.** `plan.go:DaemonApproval.valid()` rejects tag-only images. A's live SPIRE agent uses `localhost/cmtc-spire-agent:delegated-0f8fe4d681`, so primary must change that DS to the independently CRI-verified digest of the *same exact image content*, then wait for replacement Pods. Pin the ztunnel DS similarly before approval. An approval digest paired with a tag-only Pod will not match. This is an actual configuration gate, not a request for broader security authority.
5. The old `approval()` helper assumes agent/delegate namespace `cilium-spire` and delegate container `probe`. Production `ztunnel-cilium` uses `kube-system` / `istio-proxy`; build Options directly in the same existing JSON schema. `Options` explicitly supports distinct agent/delegate namespaces. Use namespace-specific RBAC. Do not mis-pin a diagnostic probe as production ztunnel.
6. Live A server StatefulSet UID `38a3116a-b5db-43b6-b12f-c821816a44f0`, RV130909 when read. Original two containers `spire-server`, `register-agent-node`; no initContainers; existing socket emptyDir. B public resource names showed only the SPIRE agent DS in cilium-spire, no diagnostic delegate. The production delegate is being activated by primary; snapshot its real UID after creation.
7. Live A socket stat: parent `0:1000:2777`, socket `1000:1000:770`. `DialServerSocket()` correctly refuses a world-searchable parent. **Reuse existing `sidecar_template()` init**: in a *new Pod's emptyDir* it checks root:1000 and emptiness and changes only that private server directory to00770. It restricts access. It does not change SPIRE's socket mode or agent Admin DAC. Do not chmod the existing populated directory, change agent Admin700, add proxy access to Admin, or edit SPIRE server signer/config/PVC.
8. `Source.Collect()` accepts current Pending and Running daemon Pods, so registrar can register a correctly pinned ztunnel before ztunnel becomes Ready. This avoids a delegate-readiness cycle. It still requires exact namespace/SA/controller/container image and current node/SPIRE-agent incarnation.
9. Empty `namespaces: []` is valid. It starts only agent aliases and production delegate registrations (normally four rows on two nodes). Do that first while no application namespace is enrolled. Later add only explicit workload namespace+SA UIDs and retain the same installationID if replacing config. A label alone does not authorize an arbitrary namespace.
10. Prometheus existing `cmtc` job selects Pod label `security.cmtc.io/metrics=true` plus **container port name `metrics`**. Add Pod label `app.kubernetes.io/name=cmtc-spire-registrar` for its component label. Metrics bind via downward `POD_IP` and `--metrics-bind-address=pod`, exact Pod IP:18087, never wildcard/loopback. Health remains18086.

## Pins and retained authority

Cluster UIDs: A `bb7182c7-de95-4e70-816a-a1400d755794`; B `f2687af6-bd96-45a3-98a2-d1397a3ee244`. Existing `/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json` records exact two-node UIDs per cluster. Read ledger **public identity** only from `~/.local/share/cmtc-issuer-profile/live-a-b/ledger.json` and never reset it. Root pin `0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c`. Public authority expires A2026-10-26T03:55:11Z, B03:55:38Z. Re-prove validity before each live acceptance; do not treat a stale proof as current signer evidence.

Retain original full server template, StatefulSet UID, PVC name→UID map, public SPIRE server CM UID/RV/data hash, exact foreign registration rows, and mesh-example labels before the patch. Do not snapshot Secrets or PVC contents. Existing SPIRE server image/config need no change.

## Generate public objects and exact StatefulSet JSON patch

The following is a manifest-only operation. It does not write the API. Run it after exact image pinning and current production ztunnel DS creation. It queries metadata from both clusters and uses existing source planning functions. Save the script in the task-owned temp directory and execute with a Python environment containing the existing lab dependencies (`cryptography`). Any missing object, tag-only pin, cluster mismatch or unexpected server profile fails before deployment. The resulting files are concrete reviewable inputs to the sole live writer.

```python
# generate_registrar_plan.py -- writes only task-owned public plan artifacts
import copy, hashlib, json, os, re, subprocess, sys, uuid
from pathlib import Path
ROOT=Path('/Users/olasumbo/gitRepos/clustermest-trust-controller')
sys.path.insert(0,str(ROOT/'scripts/lab/spire'))
import qualify_registrar as r
BASE=Path('/private/tmp/cmtc-primary-operations-20261025/registrar-live-plan')
BASE.mkdir(mode=0o700,exist_ok=False)
K='/private/tmp/cmtc-a-b-20261024.kubeconfig'
IMAGE='localhost/cmtc-spire-registrar@sha256:472a1164e46f570b87d15eff7272a4a48ede44e0a6720102395e4e73606a36fd'
PINS=json.loads(Path('/private/tmp/cmtc-spire-ca-opaque-20261024/cluster-pins.json').read_text())
OWNER='current-96cbc9eeca-'+str(uuid.uuid4())[:8]
def get(c,kind,name=None,ns=None):
    a=['kubectl','--kubeconfig='+K,'--context=kind-'+c]
    if ns:a+=['-n',ns]
    a+=['get',kind]
    if name:a+=[name]
    a+=['-o','json']
    p=subprocess.run(a,text=True,capture_output=True,timeout=20,check=True)
    return json.loads(p.stdout)
def save(p,o):p.write_text(json.dumps(o,indent=2)+'\n')
def meta(o):return r.live(o)
def image(ds,container):
    v=next(x['image'] for x in ds['spec']['template']['spec']['containers'] if x['name']==container)
    assert re.fullmatch(r'.+@sha256:[a-f0-9]{64}',v),('digest-qualified actual Pod.Spec image required',v)
    return v
def daemon(c,ns,name,container):
    d=get(c,'ds',name,ns);n=get(c,'namespace',ns)
    sa_name=d['spec']['template']['spec']['serviceAccountName'];sa=get(c,'sa',sa_name,ns)
    return {'namespace':ns,'namespaceUID':meta(n)['uid'],'name':name,'uid':meta(d)['uid'],
       'serviceAccount':sa_name,'serviceAccountUID':meta(sa)['uid'],'container':container,'image':image(d,container)}
for c in ('cmtc-a','cmtc-b'):
    out=BASE/c;out.mkdir(mode=0o700)
    assert meta(get(c,'ns','kube-system'))['uid']==PINS[c]['clusterUID']
    nodes=get(c,'nodes')['items'];assert {meta(n)['name']:meta(n)['uid'] for n in nodes}==PINS[c]['nodes']
    original=get(c,'sts','spire-server','cilium-spire');save(out/'server-before.json',original)
    save(out/'pvc-before.json',get(c,'pvc',ns='cilium-spire'))
    save(out/'server-config-before.json',get(c,'cm','spire-server','cilium-spire'))
    # Production delegate must be the actual Cilium chart DS, not diagnostic probe.
    options={'clusterName':c,'clusterUID':PINS[c]['clusterUID'],'trustDomain':c+'.mesh.example',
      'installationID':str(uuid.uuid4()),'agent':daemon(c,'cilium-spire','spire-agent','spire-agent'),
      'delegate':daemon(c,'kube-system','ztunnel-cilium','istio-proxy'),
      'namespaces':[],'excludedNamespaces':[]}
    raw=r.canonical(options);sha=r.sha(raw.encode());name='cmtc-registrar-'+sha[:16]
    save(out/'approval-options.json',options)
    cm={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':name,'namespace':'cilium-spire'},
       'immutable':True,'data':{'approval.json':raw}}
    subject=[{'kind':'ServiceAccount','name':'spire-server','namespace':'cilium-spire'}]
    common={'apiGroups':[''],'verbs':['get']}
    cr={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRole','metadata':{'name':name},'rules':[
      {**common,'resources':['namespaces'],'resourceNames':['cilium-spire','kube-system']},
      {**common,'resources':['nodes'],'resourceNames':sorted(PINS[c]['nodes'])}]}
    cb={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'ClusterRoleBinding','metadata':{'name':name},
       'subjects':subject,'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'ClusterRole','name':name}}
    objs=[cm,cr,cb]
    for ns,d in [('cilium-spire',options['agent']),('kube-system',options['delegate'])]:
        role={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':name,'namespace':ns},'rules':[
          {'apiGroups':[''],'resources':['pods'],'verbs':['get','list']},
          {**common,'resources':['serviceaccounts'],'resourceNames':[d['serviceAccount']]},
          {'apiGroups':['apps'],'resources':['daemonsets'],'verbs':['get'],'resourceNames':[d['name']]}]}
        bind={'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':name,'namespace':ns},
          'subjects':subject,'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':'Role','name':name}}
        objs += [role,bind]
    for o in objs:o['metadata'].setdefault('labels',{})['security.cmtc.io/registrar-run']=OWNER
    save(out/'objects.json',{'apiVersion':'v1','kind':'List','items':objs})
    t=r.sidecar_template(original['spec']['template'],IMAGE,name,sha)
    t['metadata'].setdefault('labels',{}).update({'security.cmtc.io/metrics':'true','app.kubernetes.io/name':'cmtc-spire-registrar'})
    h=next(x for x in t['spec']['containers'] if x['name']=='cmtc-spire-registrar')
    h['args'].append('--metrics-bind-address=pod')
    h['env']=[{'name':'POD_IP','valueFrom':{'fieldRef':{'apiVersion':'v1','fieldPath':'status.podIP'}}}]
    h['ports'].append({'name':'metrics','containerPort':18087,'protocol':'TCP'})
    save(out/'server-desired-template.json',t)
    save(out/'server-patch.json',r.template_patch(original,meta(original)['uid'],original['spec']['template'],t))
    save(out/'plan-identity.json',{'owner':OWNER,'installationID':options['installationID'],'configName':name,'approvalSHA256':sha,'source':'96cbc9eecaa95d830562c678f7e38041a17755a5','image':IMAGE,'protected':False})
```

The generated server patch **tests metadata UID, resourceVersion and complete original template** before replacing it. It preserves both original containers, server configuration, signer mounts and PVC. Never strip failed preconditions or replace a drifted template by force. Re-snapshot/review after legitimate concurrent primary changes.

Inspect image imports with the existing Colima runtime before any API write:

```sh
colima ssh --profile cmtc-cilium -- docker exec cmtc-a-worker crictl inspecti -o json localhost/cmtc-spire-registrar:current-96cbc9eeca
```

Repeat on all four nodes; require actual configurationID dfdfda..., linux/arm64, source label96cbc9e.... Resolve the tag to CRI repoDigests and correlate the running Pod imageID to those digests. A Kubernetes synthetic import digest alone is not a configurationID. Then sole primary writes each reviewed namespace's objects with `kubectl create -f .../objects.json`, recording resulting UID/RV. Use create-only, not apply-overwrite: foreign same-name collision must stop. Server-side dry-run both public objects and exact patch first. Apply exact patch using `kubectl patch sts spire-server -n cilium-spire --type=json --patch-file=.../server-patch.json`, explicit K/context. Roll out A first, verify, then B. After complete success keep both helpers running; do not call old Runner.cleanup().

## Current source / readiness / metrics acceptance

For each cluster:

```sh
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire rollout status sts/spire-server --timeout=180s
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire exec spire-server-0 -c cmtc-spire-registrar -- /cmtc-spire-registrar --version
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire exec spire-server-0 -c register-agent-node -- stat -c '%u:%g:%a:%F' /tmp/spire-server/private /tmp/spire-server/private/api.sock
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire logs spire-server-0 -c cmtc-spire-registrar --tail=100
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire exec spire-server-0 -c register-agent-node -- /bin/timeout -s KILL 12 /spire-cli/opt/spire/bin/spire-server entry show -socketPath /tmp/spire-server/private/api.sock -output json
```

Version must equal `cmtc-spire-registrar source=96cbc9eecaa95d830562c678f7e38041a17755a5`. Parent must be00770; socket must remain1000:1000:770. Node agent Admin directory remains1000:1000:700, delegated directory1000:1337:2710. Match *every* helper row by hint `cmtc-registrar/v1/<clusterUID>/<installationID>`, deterministic UUID, parent identity and exact selectors using existing `wanted(options,pod,node,agent,...,role)` / `workload_api.compare_entry`; require expiry now+15<expires_at<=now+95. With two nodes and no workload approval expect exactly2 aliases+2 delegate leaves. Foreign rows must remain byte-equivalent. Record actual Counts, not generic Ready.

Fetch metrics from the Pod IP using existing register-agent-node busybox (substitute observed actual PodIP):

```sh
kubectl --kubeconfig=/private/tmp/cmtc-a-b-20261024.kubeconfig --context=kind-cmtc-a -n cilium-spire exec spire-server-0 -c register-agent-node -- /bin/wget -qO- http://POD_IP:18087/metrics
```

Do not use127.0.0.1:18087: by design metrics do not bind loopback. A port-forward can fail because its network-namespace dial targets loopback. The busybox direct PodIP path or Prometheus scrape is the correct probe.

Query the actual Prometheus API via existing authorized port forward or API Service proxy, preserving each cluster. Examples for an explicit Prometheus local URL:

```sh
curl -fsSG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=up{job="cmtc",component="cmtc-spire-registrar"}'
curl -fsSG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=cmtc_spire_registrar_readback_available'
curl -fsSG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=time()-cmtc_spire_registrar_readback_timestamp_seconds'
curl -fsSG http://127.0.0.1:9090/api/v1/query --data-urlencode 'query=increase(cmtc_spire_registrar_reconcile_attempts_total{result="readback_ack"}[2m])'
```

Require fresh targetUP1 for both clusters, readback_available1, timestamp age<=20s, and actual advancing readback_ack counter on a5s scrape. Check actual `/api/v1/targets` discovered address=PodIP:18087, component/cluster/node labels and no duplicate registrar target. Do not claim nonzero retry/deletion measurements until the affected actual failure/recovery run creates them. The four counters partition their own distinct operations; no common pie denominator across reconciliation, retry, whole inventory withdrawal and entry deletion.

## Failure and recovery: operational checks using owned RBAC

Use the fresh registrar Role only. Snapshot its full UID/RV/rules after creation. Use JSON Patch tests UID/RV/rules then remove the **pods get/list rule** from its cilium-spire Role temporarily. Do not mutate SPIRE agent/delegate DS, namespace UID, unrelated RBAC or applications for this failure. On the next10s registrar pass, expect actual API Forbidden, `reconcile-withdraw` log with attempt/elapsed/deadline/nextRetry, readback_available0 and zero timestamp, reconciliation error+failure withdrawal counters advance, and all exact installation rows removed by private SPIRE readback. Foreign rows remain unchanged. At least one subsequent pass must occur to prove retries_total{cause="error"} advances: a scheduled but canceled retry does not count.

Restore the exact saved Role rules with current UID/RV/rules preconditions. Require a later actual readback_ack, readback_available1 and exact current rows re-created with bounded expiry. Require actual retry counter increases, not merely log text. Save pre/failure/recovery raw metrics and actual entries with timestamps. This tests registrar source failure/withdrawal/recovery without broadening access. It does **not** prove existing workload certificates have expired/revoked or TLS traffic is denied.

For restart recovery, after both clusters pass, primary may delete only current server Pod with server-side UID+resourceVersion DeleteOptions preconditions; preserve StatefulSet/PVC and immutable config. Existing `pki.Proxy.request('DELETE', '/api/v1/namespaces/cilium-spire/pods/spire-server-0', {'apiVersion':'v1','kind':'DeleteOptions','preconditions':{'uid':podUID,'resourceVersion':podRV}})` provides the already-approved interface. Require new Pod UID, same PVCUID map and signer proof, exact image/version, fresh metric process counters (reset expected), exact current alias/delegate row readback, restored Prometheus target and existing application reachability. Do not count a new Pod's zero counters as historical failures disappearing.

## Public signer proof and workload fixture checks

Reuse `scripts/lab/spire/public_proof.py` with current PodUID and public approvalUID, root pin above, existing approved server image, and `--registrar-image` set to the current digest. CLI requires `--kubeconfig`, `--cluster`, `--cluster-uid`, `--pod-uid`, `--approval-uid`, `--root-sha256`, `--pki-module <repo>/scripts/lab/pki/pki.py`, `--server-image` and `--registrar-image`. It emits public certs only and handles its temporary mint key internally without exporting it. Preserve the public ledger and recheck expiry. Old signer proof is not sufficient after a rollout.

For registration withdrawal/native credential checks, existing `qualify_registrar.py` methods provide exact fixtures: enroll target+same-node control; `fetch_all`; remove target enrollment with UID/RV/labels preconditions; wait for exactly six target-withdrawn alias/delegate/control rows; `deny_withdrawn` brackets target explicit empty/unusable SVID with independently verified still-authorized control SVIDs; re-enroll and `fetch_all`; Pod replacement proves old entryID removed; server restart proves retained signer/PVC and fresh entry readback. This historical runner must be adapted only as an **operational wrapper**, with current source/config image constants independently bound and no competing production registrar for the same SPIFFEID. Its default diagnostic setup and cleanup are not the permanent installation. Do not run diagnostic fixture writer concurrently with the production helper on overlapping namespace/SA SPIFFEIDs: duplicate writer is deliberately refused. Native probe source/image was old758435... and is not automatically current35a6c94 qualification.

A permanent deployment with no workload namespaces proves registrar/delegate readiness only. Workload mTLS acceptance remains the main delivery mandate: current authenticated source, effective policy, local/A→B/B→A GlobalService and PodIP TCP80/8080/high-port paths, identity/policy/trust negatives, reconnect/restart and encrypted packet evidence. Registration, readback ACK, helper health, SVID and metrics are separate gates. Do not call any of them Protected.

## Rollback boundary

Do not stop the helper before withdrawing owned rows. For diagnostic fixture cleanup the existing runner deletes its exact owned delegate first, waits owned_rows empty, then restores original template and proves signer/PVC unchanged. **Never delete the production ztunnel DS merely to reuse that cleanup algorithm.** For permanent installation rollback, prefer restore a valid same-installation approval with namespaces=[] to withdraw workload rows while retaining delegates; then use controlled owned RBAC denial as above to withdraw all helper rows while helper remains active. Verify exact owned inventory empty, restore original server template using fresh UID/RV/complete-installed-template tests, and then remove only recorded owned config/RBAC objects with UID/RV deletion preconditions. Preserve ztunnel/cilium runtime ownership and expect their real health to reflect unavailable delegate entitlement. If shutdown timeout prevents withdrawal, bounded90s registration expiry is a fallback, not an acknowledged successful deletion; label that limitation and wait exact absence before acceptance.

## Actual blocks and scope

The observed tag-only SPIRE agent approval mismatch and missing production delegate at snapshot time must be resolved by primary. No additional authority for signer/private keys, agent Admin DAC, upstream merges, registry publication or manual CI is required or proposed. Read-only API access succeeded after normal sandbox escalation; no auto-review rejection occurred. All writes described above remain unexecuted by this auditor.
