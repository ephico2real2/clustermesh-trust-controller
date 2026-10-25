# Live workload mTLS test proposal — UNRUN

Prepared against Cilium 51170b123988cda86aaea1bef3ccd95d221b8bbb, ztunnel 35a6c9403eb5c00b1b79aafe2851f423cd195540 and SPIRE 0f8fe4d6812c388be9ffd7b6d160e67b59163d95. Primary owns operational compiler/live writes; Opus owns product source. This is an operational fixture proposal only. No test stage, workload execution, namespace label, SPIRE mutation, capture or live restart was run by this audit. Script received a Python syntax-only `compile()` check. No Go/Rust compilation, branch/worktree changes, Secret/private-key reads, CI or publication.

Runnable proposal: `/private/tmp/cmtc-primary-operations-20261025/live_mtls_fixture_proposal.py`. Every stage requires `--execute`; primary must review before use. It uses only the two explicit owned contexts and verifies kube-system UIDs. It creates only `cmtc-live-mtls` and `cmtc-live-mtls-unauth`, records namespace UIDs before subsequent operations and refuses adoption of an existing namespace. All request targets are constructed from current owned Pod IPs/service names. No arbitrary shell/user payload is accepted. No automatic cleanup or production rollback exists.

Use edit/configure → owned clusters → traffic/failure/recovery → exact host-Podman image checks. Current image/source pins and final qualification must be recorded by primary. Application success is insufficient for mTLS: require authenticated peer identity, public certificate chain, effective policy verdict and packet/metrics correlation. Cross-node/cross-cluster source-egress delivery remains R7 and is expected to deny; do not relax guards.

## Smallest first request

Wait until both Cilium agents on A are Ready with exact revisions, A proxies are Ready with committed issuer-profile checkpoints, and exact per-Pod proxy delegate registrations are active. All replacement Pods must start with `ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP=false` once initial checkpoints are committed. Keep OnDelete while removing the bootstrap template env; never delete/rebootstrap history. Add proxy `AUTHZ_POLICY_INFO_LOGGING=true` before first creation if possible (`ztunnel/src/config.rs:138`).

Set these task-specific shell variables:

```sh
K=/private/tmp/cmtc-a-b-20261024.kubeconfig
P=/private/tmp/cmtc-primary-operations-20261025/live_mtls_fixture_proposal.py
E=/private/tmp/cmtc-primary-operations-20261025/live-mtls-fixture
```

Create both clusters' initially UNENROLLED fixtures before the complete baseline so both global service exports can sync:

```sh
python3 "$P" create --cluster cmtc-a --out "$E" --execute
python3 "$P" create --cluster cmtc-b --out "$E" --execute
python3 "$P" probe --cluster cmtc-a --out "$E" --scope first --expect allow --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope first --expect allow --execute
```

Each `first` selects exactly3 requests: worker-client→worker-server at 80, 8080 and 31337. These are explicit **plaintext baselines**, not mTLS evidence. Request completion markers distinguish failure to exec from actual curl/network failure. Script saves full headers/body/returncode and requires HTTP 200 plus expected serving-cluster JSON. A baseline failure is a fixture/reachability blocker; do not proceed by weakening guards.

Optional full plaintext baseline after service synchronization:

```sh
python3 "$P" probe --cluster cmtc-a --out "$E" --scope all --expect allow --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope all --expect allow --execute
```

Full all-scope matrix is36 requests per source cluster,72 total: 2same-node destinations+2cross-node+4remote Pod destinations+4global-service destinations, each at3 ports. No skipped/zero-selected case counts as evidence.

Register exact **workload** entries (proxy delegates remain owned by the activation owner):

```sh
python3 "$P" register --cluster cmtc-a --out "$E" --execute
python3 "$P" register --cluster cmtc-b --out "$E" --execute
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
```

Start selected fixture packet captures as below. Then label **A only** and collect first actual request:

```sh
python3 "$P" enroll --cluster cmtc-a --out "$E" --execute
# Wait for explicit capture/address/policy/profile evidence for the four exact Pod UIDs.
python3 "$P" probe --cluster cmtc-a --out "$E" --scope first --expect allow --execute
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
```

The first positive stage is3 fresh HTTP requests at all 3 ports. `probe` checks traffic only and prints `securityReasonVerified:false` even on success. Primary must correlate peer certs/identities/policy/packets before calling it workload mTLS. If the first request fails, take evidence immediately and report actual failure; do not retry indefinitely or skip31337.

Once A same-node is established, activate B immediately:

```sh
python3 "$P" enroll --cluster cmtc-b --out "$E" --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope first --expect allow --execute
python3 "$P" evidence --cluster cmtc-b --out "$E" --execute
```

## Fixture definitions and identity

The script reads ONLY public `mesh-example/rebel-base` Deployment and its public `rebel-base-response` and `rebel-base-nginx` ConfigMaps. It asserts one container `nginx:1.27-alpine`, volume names exactlyhtml/nginx-conf, both ConfigMaps; no Secret/projected token volume is copied. Source CM data observed:

- `rebel-base-response:index.html`: JSON cluster cmtc-a/cmtc-b and serving message.
- `rebel-base-nginx:nginx.conf`: listen80,8080,31337; JSON Content-Type; X-CMTC-Cluster and X-CMTC-Pod response headers; static html root.

Each cluster gets `server-worker`, `server-control-plane` (SA rebel-base) and `client-worker`, `client-control-plane` (SA mesh-client, `curlimages/curl:8.14.1`). All are pinned to the corresponding current owned node, service account automountfalse. No privileges/host mounts. Namespace is initially unlabeled for mTLS. Both namespaces and Pods carry `security.cmtc.io/test-owner=cmtc-primary-live-mtls-20261025`.

Each cluster also gets two `unregistered-*` curl Pods in the separate **UNENROLLED** `cmtc-live-mtls-unauth` namespace, SA unregistered, no SPIRE entry. This avoids poisoning initial main-namespace reconciliation: Cilium's strict EnrollmentReconciler revalidates ALL namespace endpoints and emits xDS only after every revalidation succeeds (`pkg/ztunnel/reconciler/reconciler.go:154-184`). Introducing an unregistered/quarantined endpoint to the main enrolled namespace before first positive could stall the group. An unregistered client in the separate namespace tests rejected plaintext/no-credential input; it does NOT by itself prove denial of a forged SVID.

Service `server-cmtc-a` and `server-cmtc-b` exists in both clusters, with `service.cilium.io/global=true`. Selector `test-role:server,serving-cluster:<target cluster>` exports only that serving cluster's endpoints. Each has all 3 ports. Direct Pod IP is used for deterministic same-node proof. Global Services may select worker or control-plane: they cannot establish deterministic same-node success while R7 cross-node policy is missing.

Entry command uses exact existing local CLI:

```
kubectl --kubeconfig "$K" --context kind-cmtc-a -n cilium-spire exec spire-server-0 -c register-agent-node -- \
 /bin/timeout -s KILL 12 /spire-cli/opt/spire/bin/spire-server entry create \
 -entryID <deterministic owned ID> \
 -parentID spiffe://cmtc-a.mesh.example/ns/cilium-spire/sa/spire-agent \
 -spiffeID spiffe://cmtc-a.mesh.example/ns/cmtc-live-mtls/sa/mesh-client \
 -x509SVIDTTL 120 \
 -selector k8s:ns:cmtc-live-mtls -selector k8s:sa:mesh-client \
 -selector k8s:pod-uid:<current exact UID> -selector k8s:node-name:cmtc-a-worker \
 -socketPath /tmp/spire-server/private/api.sock
```

Each of4Pod UIDs receives its own entry. Server identity ends `/sa/rebel-base`. This permits the same SA identity on different nodes while selectors and workload cache UID distinguish actual incarnations. Script readback asserts entryID, numericTTL120, exact SPIFFE ID and parent from `spiffe_id.trust_domain/path` and `parent_id.*`, and the exact selector set. Source JSON schema verified in `spire/cmd/spire-server/cli/entry/show_test.go:507-541`. Registration ledger is persisted before writes so partial failure remains recoverable. Registration stage refuses rerun if ledger exists. Inspect missing entries explicitly rather than deleting ledger to retry blindly.

## Measurement and certificates

`evidence` saves current test Pods and CiliumEndpoints, bounded 10-minute/3000-line proxy+agent logs, proxy15000/config_dump, proxy15020/metrics and agent9962/metrics for both nodes. It uses only task-owned localhost port-forward subprocesses and terminates only those. It suppresses output containing PRIVATE KEY; no Secret resource is requested. Public certificate PEMs are exported from certdump only. Timestamps separate before/after snapshots.

Audited ztunnel configdump schema:

- `certificates[].identity`, optional`uid`, `state`.
- `certificates[].certChain[].pem` is **BASE64 encoded public PEM**, not literal PEM.
- public root records are `rootCerts[]`.
- `config.auth` is excluded by serde; no private-key field exists in certificate dump (`src/admin.rs:65-95,222-251`; `src/config.rs:308-319`).

Assert Available certs for both worker source/destination exact UIDs, matching expected SPIFFE SANs and current validity. Verify both sslclient/sslserver chains against the independently pinned organization root, approved direct SPIRE issuer and parent chain. Existing delegated probe helper performs this chain validation and can be reused as reference; configdump leaf alone is insufficient. Never replace independent orgroot pin with a root supplied solely by same dump.

Expected telemetry (verify actual scrape names, never manufacture series): `istio_tls_handshakes_total{reporter,result}`, `istio_tls_handshake_duration_seconds_*`, `istio_tls_connections_active`, and connection metrics with `connection_security_policy="mutual_tls"`, source/destinationprincipal and workload labels. `src/proxy/metrics.rs:470-508` registers these at the real TLS accept/connect owner; `src/metrics.rs:36` applies istio prefix. Cilium native policy events are `cilium_ztunnel_xds_effective_policy_events_total{event}`. Record before/after deltas per reporter, with actual selected request counts.

A pool can reuse one TLS connection for many HTTP requests. HTTP requests, policy decisions and completed TLS handshakes are different denominators. Successful first request should establish actual TLS; later handshake delta0 can be valid reuse. A TLS handshake that succeeds before authorizationDENY still is not an allowed application request. Do not sum source+destination as two independent application requests.

Source access logs emit authenticated `src.identity`/`dst.identity` only when connection securitypolicy is mutual_tls (`src/proxy/metrics.rs:763-781,906-929`). Correlate exact source IP, destination IP, application port, Pod UID, time, direction and policy verdict. Enable AUTHZ_POLICY_INFO_LOGGING before first proxy creation where possible; otherwise bounded admin logging adjustment needs separate primary review and restoration, not an unplanned restart.

## Scoped packet capture

Same-node HBONE is implemented: source's outbound HBONE test expects targetPodIP:15008 even for local-node destination (`ztunnel/src/proxy/outbound.rs:1997-2027`). Source application HTTP may appear in the workload netns between app and proxy, which is expected. Judge plaintext leakage on the actual external veth/node path, not every loopback packet. Keep15008TLS evidence separate from WireGuard/IPsec/node encryption.

Use existing Colima Docker runtime; do not switch provider or package an image just to capture. First verify tools are present on owned node without installing or changing global settings:

```sh
docker --context colima-cmtc-cilium exec cmtc-a-worker sh -c 'command -v tcpdump; command -v nsenter; command -v timeout; command -v crictl'
```

If present, primary records current worker-client+worker-server IPs and sandbox PID from exact current testPod UID using `crictl pods -o json` + `crictl inspectp`; assert sandbox metadataUID and node before namespace access. Capture only the two owned fixtureIPs. Example (variables must come from current verified namespace ledger):

```sh
docker --context colima-cmtc-cilium exec cmtc-a-worker \
 timeout -s INT 25 tcpdump -i any -U -s 0 -w - \
 "tcp port 15008 and (host $SRC_IP or host $DST_IP)" > "$E/a-worker-node-hbone.pcap" &
CAPTURE_PID=$!
# Also capture the current source sandbox network namespace if local routing bypasses host interfaces.
docker --context colima-cmtc-cilium exec cmtc-a-worker \
 timeout -s INT 25 nsenter -t "$SOURCE_SANDBOX_PID" -n tcpdump -i any -U -s 0 -w - \
 "tcp port 15008 and (host $SRC_IP or host $DST_IP)" > "$E/a-worker-client-netns-hbone.pcap" &
NETNS_CAPTURE_PID=$!
python3 "$P" probe --cluster cmtc-a --out "$E" --scope first --expect allow --execute
wait "$CAPTURE_PID"
wait "$NETNS_CAPTURE_PID"
```

Record timeout/tcpdump exit behavior explicitly; an empty PCAP is no proof. Analyze TLS record traffic on15008 and absence of appHTTP on external targetapplication port path. Capture stderr separately in evidence. Missing node capture tools is a real evidence dependency; use an already qualified task-owned capture tool under primaryreview, not a new host install or broad privileged unscoped capture. Do not set TLS session key log env or export workload private keys.

## Negative, recovery and bounded load

Run both same-node paths after first positive (6requests percluster). Run unregistered same-node input at all 3 ports on bothnodes:

```sh
python3 "$P" probe --cluster cmtc-a --out "$E" --scope same --expect allow --execute
python3 "$P" probe --cluster cmtc-a --out "$E" --scope negative --expect deny --execute
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
```

A curltimeout proves no response, not its securityreason. Require auth/policy/quarantine denial at the owning boundary; exec/connectivityfixture failures cannot pass a securitytest. Script aborts if kubectl exec itself fails. RepeatB.

Credential withdrawal/recovery, after successfulpositive:

```sh
python3 "$P" withdraw --cluster cmtc-a --out "$E" --pod client-worker --execute
# Poll public certcache and credential validity. Allow last already issued 120s SVID + clock margin to expire.
# Keep first test on workeronly; use firstscope below.
python3 "$P" probe --cluster cmtc-a --out "$E" --scope first --expect deny --execute
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
python3 "$P" recover --cluster cmtc-a --out "$E" --pod client-worker --execute
# Wait current credential+fresh session/profile+policy readiness, without toggling Required.
python3 "$P" probe --cluster cmtc-a --out "$E" --scope first --expect allow --execute
```

Withdrawal is not instantaneous revocation of an alreadyissued certificate. Existing pooled TLS connections may survive unless source runtime specifically tears them down on credential expiry; if they do, record it. If traffic persists beyond approved validity and fresh TLS cannot be established, report exact observed cache/pool semantics; do not call credential withdrawal a successful immediate fail-closed test. Deterministic no-cache unregistered negative runs separately.

Port-policy denial proposal (new owned CNP only):

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: live-deny-8080
  namespace: cmtc-live-mtls
  labels: {security.cmtc.io/test-owner: cmtc-primary-live-mtls-20261025}
spec:
  endpointSelector:
    matchLabels: {test-role: server}
  ingressDeny:
  - fromEndpoints:
    - matchLabels: {test-role: client}
    toPorts:
    - ports: [{port: "8080", protocol: TCP}]
```

Applyonly to main fixture in onecluster. Wait realized policyrevision and xDSowner change. Raw ingress deny may activate default deny for selected server's other ingress: inspect source realized policy semantics and add explicit fixture-only ALLOW rule for80/8080/31337 if baseline default policy changes. Do not assert80/31337remain allowed without measuring. Request eachport individually using script curl method/explicitkubectl; require8080rejection plus exact effective policy. Delete CNP by UID/resourceVersion precondition, wait revision and require8080recovery. L7/CIDR/local-scope unsupported policy must failclosed; do not substitute a synthetic xDS ALLOW.

After highport31337 success + negative + recovery, serial bounded load of120 same-node requests percluster:

```sh
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
python3 "$P" probe --cluster cmtc-a --out "$E" --scope same --expect allow --repeat 20 --execute
python3 "$P" evidence --cluster cmtc-a --out "$E" --execute
```

RepeatB. This is serial validation load, not a throughput benchmark. Record actual counts/errors; retain packet/log/metrics timestamps from same interval. Dashboard evidence uses actual scrape values; HTTP requests and handshakes remain separate.

## Cross-node and two-cluster results (R7 expected deny)

```sh
python3 "$P" probe --cluster cmtc-a --out "$E" --scope crossnode --expect deny --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope crossnode --expect deny --execute
python3 "$P" probe --cluster cmtc-a --out "$E" --scope crosscluster --expect deny --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope crosscluster --expect deny --execute
```

Cross-node 6 requests percluster; cross-cluster 12 per direction, 24 total. Collect explicit policy verdicts. A surprisingHTTP 200 is an unexpected security result that needs source/evidence review, not proof R7 is complete. Missing remote Workload projection can cause earlier unresolved-destination deny; distinguish that from demonstrated ingress∩source-egress policy rejection.

Remote Global Service paths (6 requests per source cluster, 12 total):

```sh
python3 "$P" probe --cluster cmtc-a --out "$E" --scope remote-global --expect deny --execute
python3 "$P" probe --cluster cmtc-b --out "$E" --scope remote-global --expect deny --execute
```

`--scope global --expect deny` covers BOTH local and remote services and is unsuitable for a blanket denial expectation: the local service can select a same-node allowed backend. Keep remote Global Service tests separate from Pod-IP tests. For local service calls, record each selected backend and its node; mixed same-node/cross-node results remain possible while R7 is missing.

## Recovery and cleanup constraints

- Restart one ztunnel only after bootstrap false and durable checkpoint; update exact delegate entry to new Pod UID before credentials, preserve current workload entries if their UIDs are unchanged. Repeatfirst positive/negative and peer chain checks. Script intentionally does not restart proxy or agent.
- Namespace label removal is NOT a plaintext rollback. Strict reconciler returns ErrStrictLiveUnenrollment while endpoints exist and retains Required until sandbox retirement (`reconciler.go:190-213`). Do not use label toggles for recovery.
- Missing/stale/NACKed policy/trust mismatch/ADS disconnect/kernel-write failure need their own deterministic isolated cases; do not corrupt production issuer approval/checkpoint/root pins. Keep these open if not run.
- Remove only SPIRE entry IDs from exact ledger; no selector-wide deletion. If a Pod UID changed, old entry recovery must refuse. Re-register new incarnation explicitly under primary review.
- Delete test namespaces ONLY after ledger UID andowner label match, with API UID/resourceVersion preconditions usingexisting owned UID-delete helper or direct DeleteOptions. Removing the whole owned namespace retires its pods; preserve every existing mesh-example fixture and completed load Pod.
- Preserve full positive/negative/recovery logs, exact source/image IDs, failure counts, and packet analysis. Operational proposal oragent assertion is not evidence. Keep CI/registry deferred and every working branch/worktree.
