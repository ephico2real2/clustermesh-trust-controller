# CMTC operational activation audit — 2026-10-25

Read-only audit. No product implementation, compilation, Git mutations, API writes, or live changes were performed. Report is an operational proposal, not mTLS evidence. Exact audited source: Cilium `51170b123988cda86aaea1bef3ccd95d221b8bbb`, ztunnel `35a6c9403eb5c00b1b79aafe2851f423cd195540`, SPIRE `0f8fe4d6812c388be9ffd7b6d160e67b59163d95`, under `/private/tmp/cmtc-opus-final-20261025`. TokenSave root graph is one commit stale; forks are unindexed; source was inspected directly. Primary has sole operational writer/compiler leases. Product source remains Opus-owned. Follow edit/configure → owned cmtc-a/cmtc-b → traffic/failure/recovery → host Podman exact-image validation. No CI, registry publication, retired lab scripts, root-key reads, Secret reads, Admin DAC changes, or Required-guard relaxation.

## Immediate activation boundaries

Cilium source permits the assembled runtime when strict mTLS, SPIRE, effective policy quarantine, direct-origin membership and issuer-profile pins are all configured (`pkg/ztunnel/cell.go:68`). Effective policy compiles only captured local endpoints in this agent registry (`pkg/ztunnel/xds/effective_policy.go:157-219`). Same-node sources can work. Cross-node and cross-cluster sources have no realized egress delivery (R7); preserve denial and report it. ADS client authentication, node-scoped membership writer/provenance, permanent kernel-map write failure, retained captures and ID/IP reuse remain open. No combined Protected claim follows from activation.

No additional Go/Rust implementation is required merely to assemble the already implemented same-node configuration. Actual startup can still expose runtime defects and must be verified.

## Public live inventory (read 2026-10-25T15:43Z)

| Value | cmtc-a | cmtc-b |
|---|---|---|
| Context | kind-cmtc-a | kind-cmtc-b |
| kube-system UID | bb7182c7-de95-4e70-816a-a1400d755794 | f2687af6-bd96-45a3-98a2-d1397a3ee244 |
| numeric Cilium cluster ID | 1 | 2 |
| ztunnel CLUSTER_ID | cmtc-a | cmtc-b |
| trust domain | cmtc-a.mesh.example | cmtc-b.mesh.example |
| worker IP | 172.18.0.2 | 172.18.0.5 |
| control-plane IP | 172.18.0.3 | 172.18.0.4 |
| ClusterMesh Service IP | 10.11.61.167 | 10.21.128.95 |
| ClusterMesh NodePort | 32379 | 32379 |
| approval UID | 902e1117-142f-4c91-ada7-65e57b0863e6 | ba07d872-3ccb-4396-bd60-828f615a9cde |
| publication UID | fbc7b3c2-00f1-4787-a149-fca76e274c4e | cb6e0317-d887-49be-b265-d24d896c35ef |

Public cert-manager CertificateRequest `kube-system/clustermesh-apiserver-server-cert-2` yields these server SPKI SHA256 pins:
- A `57eec8f36902aceb097c956c54736cb1e9f8569798a0b8f7649f0eca9dba99ad`.
- B `034f5e79a9e5d58ca1c1f624f1415f1dca787966b6740637aa55ebda6726210a`.

Both server certs have CN `clustermesh-apiserver.kube-system.svc` and SANs `clustermesh-apiserver.kube-system.svc`, `*.mesh.cilium.io`, 127.0.0.1, ::1. Before calling remote provenance verified, confirm the public certificate currently served on NodePort has that SPKI. CertificateRequest contents are public; no Secret/private key was read.

**Two independent CAs:** membership etcd TLS uses ConfigMap `kube-system/cmtc-public-root`, key `ca.crt`, CN `CMTC disposable lab root`. Issuer-profile trust uses the organization root, DER certificate SHA256 `0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c`. Do not substitute either for the other.

Approval generation 1 expires 2026-10-26T03:55:11Z. Approval digest is `3ee827dd1f39ff42dd113b2a87f7538ec6ca73af7c5cc0fe0abf136f81b20baf`. Publication sequences/digests/validUntil renew every ~10 seconds and must be sampled freshly when generating virgin installation pins. Do not reset an existing checkpoint or lower its floor.

## Certificates — complete resource definitions

Apply to ONE explicit owned context, initially A. For B replace only the writer commonName suffix. Cert-manager creates/mounts private keys; neither operator needs to read them.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ztunnel-membership-writer
  namespace: kube-system
spec:
  secretName: ztunnel-membership-writer
  commonName: ztunnel-membership-writer-cmtc-a
  duration: 24h
  renewBefore: 1h
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  usages: [digital signature, client auth]
  issuerRef:
    name: cmtc-lab-intermediate
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ztunnel-origin-reader
  namespace: kube-system
spec:
  secretName: ztunnel-origin-reader
  commonName: ztunnel-origin-reader
  duration: 24h
  renewBefore: 1h
  privateKey:
    algorithm: ECDSA
    size: 256
    rotationPolicy: Always
  usages: [digital signature, client auth]
  issuerRef:
    name: cmtc-lab-intermediate
    kind: ClusterIssuer
    group: cert-manager.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cilium-ztunnel-issuer-profile
  namespace: cmtc-system
rules:
- apiGroups: [""]
  resources: [configmaps]
  resourceNames: [cmtc-issuer-approval-g1, cmtc-issuer-publication]
  verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cilium-ztunnel-issuer-profile
  namespace: cmtc-system
subjects:
- kind: ServiceAccount
  name: cilium
  namespace: kube-system
roleRef:
  kind: Role
  name: cilium-ztunnel-issuer-profile
  apiGroup: rbac.authorization.k8s.io
```

Wait Certificate Ready and inspect public CertificateRequest chain/EKU/CN. Test `kubectl auth can-i get configmap/cmtc-issuer-publication -n cmtc-system --as=system:serviceaccount:kube-system:cilium` with the explicit kubeconfig/context. etcd-init at audited source provisions the writer CN suffixed by cluster and the read-only reader; writer is cluster-wide, not node-scoped. (`pkg/kvstore/etcdinit/init.go:150-216`.)

## Membership and origin config — complete A proposal

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ztunnel-membership-etcd
  namespace: kube-system
data:
  etcd.yaml: |
    endpoints:
    - https://clustermesh-apiserver.kube-system.svc:2379
    trusted-ca-file: /var/lib/cilium/ztunnel-membership/ca.crt
    cert-file: /var/lib/cilium/ztunnel-membership/tls.crt
    key-file: /var/lib/cilium/ztunnel-membership/tls.key
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: ztunnel-origin-config
  namespace: kube-system
data:
  cmtc-b: |
    endpoints:
    - https://cmtc-b.mesh.cilium.io:32379
    trusted-ca-file: /var/lib/cilium/clustermesh-origin/ca.crt
    cert-file: /var/lib/cilium/clustermesh-origin/tls.crt
    key-file: /var/lib/cilium/clustermesh-origin/tls.key
    cilium-host-aliases:
    - hostname: cmtc-b.mesh.cilium.io
      ips: [172.18.0.4, 172.18.0.5]
    cilium-remote-peer:
      cluster-id: 2
      spki-sha256: [034f5e79a9e5d58ca1c1f624f1415f1dca787966b6740637aa55ebda6726210a]
```

B reverses the origin key/endpoint/alias to `cmtc-a`, `cmtc-a.mesh.cilium.io`, IPs `[172.18.0.3,172.18.0.2]`, cluster-id 1 and A SPKI pin above. Both use their own reader Certificate Secret: shared CA, dedicated CN reader accepted remotely. Do not reuse ClusterMesh admin credentials. Origin loader validates config/TLS files inside ONE resolved read-only mount, strict permissions, full reader chain and expiry (`pkg/ztunnel/remote_workload/origin_supervisor.go:109-238`). Absolute TLS file paths must resolve inside that directory; sibling mounts fail.

Add these volumes and mounts to the EXISTING Cilium DS, preserving all unrelated fields. A/B origin CM key differs; defaultMode 384 =0600 in JSON/YAML decimal.

```yaml
# .spec.template.spec.volumes additions
- name: ztunnel-membership
  projected:
    defaultMode: 384
    sources:
    - configMap:
        name: ztunnel-membership-etcd
        items: [{key: etcd.yaml, path: etcd.yaml}]
    - configMap:
        name: cmtc-public-root
        items: [{key: ca.crt, path: ca.crt}]
    - secret:
        name: ztunnel-membership-writer
        items: [{key: tls.crt, path: tls.crt}, {key: tls.key, path: tls.key}]
- name: ztunnel-origin
  projected:
    defaultMode: 384
    sources:
    - configMap:
        name: ztunnel-origin-config
        items: [{key: cmtc-b, path: cmtc-b}]
    - configMap:
        name: cmtc-public-root
        items: [{key: ca.crt, path: ca.crt}]
    - secret:
        name: ztunnel-origin-reader
        items: [{key: tls.crt, path: tls.crt}, {key: tls.key, path: tls.key}]
- name: ztunnel-issuer-pins
  hostPath: {path: /etc/cmtc/ztunnel-issuer-pins, type: Directory}
- name: cilium-ztunnel-secrets
  secret:
    secretName: cilium-ztunnel-secrets
    defaultMode: 384
    items:
    - {key: bootstrap-private.key, path: bootstrap-private.key}
    - {key: bootstrap-root.crt, path: bootstrap-root.crt}
# cilium-agent container volumeMounts additions
- {name: ztunnel-membership, mountPath: /var/lib/cilium/ztunnel-membership, readOnly: true}
- {name: ztunnel-origin, mountPath: /var/lib/cilium/clustermesh-origin, readOnly: true}
- {name: ztunnel-issuer-pins, mountPath: /etc/cmtc/ztunnel-issuer-pins, readOnly: true}
- {name: cilium-ztunnel-secrets, mountPath: /etc/ztunnel, readOnly: true}
```

No general agent `kvstore` option: CRD identity allocation and ordinary agent KVStore stay unchanged. Source publisher opens the dedicated etcd connection (`pkg/ztunnel/admission/source_membership.go:34`). Projected Secret refreshes are visible without exporting their contents.

## Fresh ADS bootstrap

Create a fresh local key and server certificate for each cluster (0700 temp dir,0600 key). Certificate SAN DNS localhost and IP127.0.0.1, EKU serverAuth, BasicConstraints CA:FALSE. Audited source uses `credentials.NewServerTLSFromFile` at `/etc/ztunnel/bootstrap-root.crt` and `/etc/ztunnel/bootstrap-private.key` (`pkg/ztunnel/ca/ca_server.go:29-34,75-78`). This is server-only loopback TLS: authenticating ztunnel clients remains an implementation gate.

```sh
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -days 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:FALSE' \
  -addext 'keyUsage=critical,digitalSignature' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$OPS/bootstrap-private.key" -out "$OPS/bootstrap-root.crt"
kubectl --kubeconfig "$K" --context "$CTX" -n kube-system create secret generic cilium-ztunnel-secrets \
  --from-file=bootstrap-private.key="$OPS/bootstrap-private.key" \
  --from-file=bootstrap-root.crt="$OPS/bootstrap-root.crt"
```

Define OPS/K/CTX explicitly; use one directory per cluster. Do not emit a Secret YAML to stdout or evidence. If Secret already exists, inspect metadata only and do not overwrite a different owner's resource. Proxy chart projects only the public certificate. No internal CA root/key is required with `ztunnel-ca-type=spire`.

## Pins, checkpoint and agent flags

Create one ROOT-OWNED regular file on each kind node at `/etc/cmtc/ztunnel-issuer-pins/pins.json`, mode0644 (no group/world writes), parent0755. A single per-node directory mount supports both agents/proxies while avoiding a file symlink rejected by O_NOFOLLOW. Format (sample fresh sequence/digest; preserve independent UID/root verification):

```json
{"cluster":"cmtc-a","node":"cmtc-a-worker","sourceNamespace":"cmtc-system","sourceName":"cmtc-issuer-approval-g1","sourceUID":"902e1117-142f-4c91-ada7-65e57b0863e6","outputNamespace":"cmtc-system","outputName":"cmtc-issuer-publication","outputUID":"fbc7b3c2-00f1-4787-a149-fca76e274c4e","rootPins":["0c28af9e59fbb91745b731762201f3f618a25841c222fdf49f02714de6164b7c"],"minimumGeneration":"1","minimumSequence":"2633","approvalDigestAtMinimum":"3ee827dd1f39ff42dd113b2a87f7538ec6ca73af7c5cc0fe0abf136f81b20baf","publicationDigestAtMinimum":"a86a28e087da636f4d517c5c08bc8dc07130c661340576709d5464980fcdc45b"}
```

Sample was live at15:42:53Z and is an EXAMPLE FLOOR only; sample current publication before first virgin activation and freeze installation pins thereafter. The B UIDs appear in table. MinimumGeneration/Sequence are canonical positive decimal JSON STRINGS, not numeric fields. Copy with exact node name; source and output UID must not be confused with kube-system UID. Source checks root-owned regular file and rejects final symlink (`pkg/ztunnel/xds/issuer_profile.go:57-159`; ztunnel `src/xds/issuer_profile.rs:20-126`).

Precreate `/var/lib/cmtc/ztunnel-issuer-checkpoint` on each node, root:root0700. Mount RW only into ztunnel; Cilium does not need checkpoint mount. Never reset/delete checkpoint history. Provider locks its writer and validates directory/file identity.

Merge the following string-valued keys into existing `kube-system/cilium-config` (A shown):

```yaml
enable-ztunnel: "true"
ztunnel-ca-type: spire
ztunnel-require-mtls: "true"
ztunnel-effective-policy-quarantine: "true"
ztunnel-enable-remote-workload-membership: "true"
ztunnel-remote-origin-config-dir: /var/lib/cilium/clustermesh-origin
ztunnel-remote-origin-client-common-name: ztunnel-origin-reader
ztunnel-source-membership-etcd-config: /var/lib/cilium/ztunnel-membership/etcd.yaml
ztunnel-issuer-profile-probe-pins: /etc/cmtc/ztunnel-issuer-pins/pins.json
mesh-auth-spiffe-trust-domain: cmtc-a.mesh.example
ztunnel-spire-external-exact-registrar: "true"
prometheus-serve-addr: :9962
```

**external-exact-registrar is an OPERATOR flag**, consumed from cilium-config, not a Cilium agent CLI flag (`operator/pkg/ztunnel/config/config.go:33,58`). Confirm operator reload/restart consumes it before any enrolled namespace can trigger broad namespace registration. Do not enable operator-owned SPIRE deployment or broaden Admin DAC. Existing exact registrar must own workload registration.

Cilium DS is OnDelete. Preserve strategy and restart one owned node at a time after config/mounts are complete. Preserve exact image/source pin, report first startup failure verbatim and stop repeated attempts until fixed. Agent becomes configured before ztunnel readiness; do not enroll application namespace until both node proxies are healthy.

## Reusable ztunnel chart renderer — complete values proposal

Use ONLY fork chart templates ztunnel/daemonset.yaml + ztunnel/serviceaccount.yaml. Do not helm upgrade the whole Cilium release; no second operator/agent deployment. `authentication.mutual.spire.enabled=true` is a chart validation requirement, not authorization to apply other chart resources.

A values file:

```yaml
serviceAccounts:
  ztunnel:
    create: true
    name: ztunnel-cilium
    automount: false
authentication:
  mutual:
    spire:
      enabled: true
      trustDomain: cmtc-a.mesh.example
      adminSocketPath: /run/cmtc-spire/cmtc-a/delegated/delegated.sock
encryption:
  enabled: true
  type: ztunnel
  ztunnel:
    ca:
      type: spire
      externalExactRegistrar: true
    requireMtls: true
    image:
      override: localhost/cmtc-ztunnel:native-35a6c9403e
      useDigest: false
      pullPolicy: Never
    spire:
      containerRuntimeSocketPath: /run/containerd/containerd.sock
    updateStrategy:
      type: OnDelete
      rollingUpdate: null
    extraEnv:
    - {name: CLUSTER_ID, value: cmtc-a}
    - {name: REQUIRE_INBOUND_MTLS, value: "true"}
    - {name: REQUIRE_MESH_HBONE, value: "true"}
    - name: MESH_EGRESS_CONFIG
      value: '{"clusters":[{"clusterId":"cmtc-a","trustDomain":"cmtc-a.mesh.example","podCidrs":["10.10.0.0/16"],"serviceCidrs":["10.11.0.0/16"]},{"clusterId":"cmtc-b","trustDomain":"cmtc-b.mesh.example","podCidrs":["10.20.0.0/16"],"serviceCidrs":["10.21.0.0/16"]}],"exceptions":[]}'
    - {name: ISSUER_PROFILE_PROBE_PINS, value: /etc/cmtc/ztunnel-issuer-pins/pins.json}
    - {name: ISSUER_PROFILE_CHECKPOINT_DIR, value: /var/lib/cmtc/ztunnel-issuer-checkpoint}
    - {name: ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP, value: "true"}
    extraVolumes:
    - name: issuer-pins
      hostPath: {path: /etc/cmtc/ztunnel-issuer-pins, type: Directory}
    - name: issuer-checkpoint
      hostPath: {path: /var/lib/cmtc/ztunnel-issuer-checkpoint, type: Directory}
    extraVolumeMounts:
    - {name: issuer-pins, mountPath: /etc/cmtc/ztunnel-issuer-pins, readOnly: true}
    - {name: issuer-checkpoint, mountPath: /var/lib/cmtc/ztunnel-issuer-checkpoint, readOnly: false}
```

```sh
helm template cilium /private/tmp/cmtc-opus-final-20261025/cilium/install/kubernetes/cilium \
  --namespace kube-system -f "$OPS/ztunnel-values.yaml" \
  --show-only templates/ztunnel/serviceaccount.yaml \
  --show-only templates/ztunnel/daemonset.yaml > "$OPS/ztunnel.yaml"
```

B changes cluster/domain/socket path only, same mesh CIDRs. Review rendered values: args `[proxy-mtls,ztunnel]`; hostNetwork=true; hostPID=true; UID0/GID1337; NET_ADMIN/SYS_ADMIN/NET_RAW only; delegated dir ONLY; CRI socket readonly; no original Admin socket; public bootstrap cert only. Chart sets XDS_ADDRESS=https://localhost:15012, XDS_ROOT_CA=/etc/ztunnel/bootstrap-root.crt, CLUSTER_DOMAIN and TRUST_DOMAIN correctly, NODE_NAME Downward API, INPOD_UDS=/var/run/cilium/ztunnel.sock. Do not use Kubernetes numeric cluster IDs as CLUSTER_ID: proxy/Cilium Workload ClusterId uses cluster name string.

**ONE-SHOT BOOTSTRAP:** the initial Pods need ISSUER_PROFILE_CHECKPOINT_BOOTSTRAP=true on genuinely empty directories. After both have durably committed profiles, PATCH DS template to remove that env or false **BEFORE ANY restart**, while OnDelete prevents automatic replacement. Existing running processes may continue with initial config. Future restarts must use false and recover existing checkpoint. A crash after initialization marker but before first state commit requires explicit recovery; never delete marker and retry bootstrap. The source refuses bootstrap on initialized directory (`ztunnel/src/state.rs:1279-1304`, `src/tls/profile_checkpoint.rs:743-789`). RollingUpdate while env=true would otherwise crash-loop every replacement. Likewise maxSurge must not create two checkpoint writers/ZDS listeners on one node.

Do not set LOCAL_XDS_PATH, XDS_ON_DEMAND=true, alternate XDS hostname, or test profile inventory: issuer-profile requires complete authenticated loopback HTTPS ADS and strict session.

## Delegate and workload entries

Use existing server-local CLI from `/private/tmp/cmtc-claude-opus-20261025/lab/scripts/spire_delegated_probe.py:92-126`:

```sh
kubectl --kubeconfig "$K" --context "$CTX" -n cilium-spire exec spire-server-0 -c register-agent-node -- \
  /bin/timeout -s KILL 12 /spire-cli/opt/spire/bin/spire-server entry create \
  -socketPath /tmp/spire-server/private/api.sock \
  -entryID "$EXACT_ENTRY_ID" \
  -parentID spiffe://cmtc-a.mesh.example/ns/cilium-spire/sa/spire-agent \
  -spiffeID spiffe://cmtc-a.mesh.example/ztunnel-proxy -x509SVIDTTL 120 \
  -selector k8s:ns:kube-system -selector k8s:sa:ztunnel-cilium \
  -selector k8s:node-name:cmtc-a-worker -selector k8s:pod-uid:"$ZTUNNEL_POD_UID"
```

One delegate entry per actual Pod UID/node. Workload entries use `/ns/<namespace>/sa/<serviceAccount>` and exact ns,sa,node-name,pod-uid selectors with the same existing parent. Read back exact entries. IDs must be recorded; remove only owned exact IDs. Proxy restart changes UID: create new exact delegate entry before requesting credentials, withdraw old entry. Native workload selectors/credential checks are proven independently by the existing 12/12 probe; they do not prove mTLS. No broad namespace entry or API expansion.

## Concrete traffic, failure, recovery commands

Existing fixture (live read): `mesh-example/mesh-client`, SA mesh-client, `curlimages/curl:8.14.1`; `mesh-example/rebel-base`, SA rebel-base, nginx1.27-alpine, ports80/8080/31337, existing config/html mounts; rebel-base has worker + control-plane Pods. Preserve these and the retained completed load Pods. Initially enroll only a new test-owned namespace cloned from the fixture (same image, mounts copied from public ConfigMaps) or explicitly owned mesh-example after exact entry readiness. A namespace label is enrollment intent only. Existing baseline_probe.sh creates UNENROLLED probe namespaces and is not a positive mTLS test.

For existing fixtures after authorized enrollment/registration (all commands specify K/CTX):

```sh
# Find exact same-node server; match client .spec.nodeName with server .spec.nodeName.
kubectl --kubeconfig "$K" --context "$CTX" -n mesh-example get pod mesh-client -o jsonpath='{.spec.nodeName}'
kubectl --kubeconfig "$K" --context "$CTX" -n mesh-example get pods -l name=rebel-base -o wide
# Set SAME_NODE_IP only from the observed same-node server.
for port in 80 8080 31337; do
  kubectl --kubeconfig "$K" --context "$CTX" -n mesh-example exec mesh-client -- \
    curl -fsS --max-time 5 "http://$SAME_NODE_IP:$port/"
done
```

Record real return body to identify cluster. A raw HTTP application request can traverse workload mTLS; claim mTLS only with proxy identity + chain + authorization + captured HBONE evidence. Correlate Cilium agent metrics `cilium_ztunnel_xds_effective_policy_events_total{event="acknowledged"|"released"|"release_refused"|"compile_failed"}` with exact Pod UID, xDS config_dump and real request. ACK/release counters alone are insufficient.

Cross-node then A→B and B→A (EXPECTED DENY at R7, not positive acceptance):

```sh
for port in 80 8080 31337; do
  kubectl --kubeconfig "$K" --context "$CTX" -n mesh-example exec mesh-client -- \
    curl -sS --fail --max-time 5 "http://$OTHER_NODE_OR_REMOTE_POD_IP:$port/"
  kubectl --kubeconfig "$K" --context "$CTX" -n mesh-example exec mesh-client -- \
    curl -sS --fail --max-time 5 "http://rebel-base-cmtc-b.mesh-example.svc.cluster.local:$port/"
done
```

Use explicit source CTX for each direction and verify chosen serving cluster. Global Service may balance across nodes: pin locality for same-node proof; do not mistake a mixed service result for a deterministic local test.

Negative/recovery steps against owned fixtures:

1. Use an UNENROLLED client Pod on the same node; request enrolled server at all 3 ports. Require explicit auth/policy rejection and no successful application response. Existing baseline probe can supply unregistered identity cases only (not same-node selection).
2. Withdraw only the owned exact workload registration with SPIRE `entry delete -entryID "$ID" -socketPath ...`; wait beyond cached credential validity (120s + clock allowance) and require new requests fail; recreate same exact current selectors and require recovery. Existing probe helper does deterministic delegate/workload withdrawal/recovery.
3. Add a test-owned CiliumNetworkPolicy ingressDeny for selected server + port 8080, require 8080 deny while 80/31337 remain according to original policy; delete by UID/resourceVersion precondition and require 8080 recover. Do not modify application/global policies. Record realized policy revision and effective compiled ALLOW/DENY.
4. Restart one ztunnel Pod by UID only AFTER bootstrap=false and checkpoint committed; require temporary deny then recovery, current exact delegate registration, fresh ADS/profile ACK, fresh policy, actual requests. Never run a second active ztunnel writer.
5. Run existing delegated negative/recovery helper (mutates its own isolated fixtures; primary only):

```sh
python3 /private/tmp/cmtc-claude-opus-20261025/lab/scripts/spire_delegated_probe.py \
 --context kind-cmtc-a --node cmtc-a-worker \
 --agent-image localhost/cmtc-spire-agent:delegated-0f8fe4d681 \
 --out "$OPS/delegated-recheck-a"
```

For positive same-node packet evidence use a task-owned capture on selected node `tcp port15008` plus exact Pod IPs. Same-node traffic may stay within node namespace/veth path: document capture interface, authenticated peer IDs and actual byte records. Cross-node application success stays unqualified until R7 delivery; failed HBONE handshakes or denied connections may still produce encrypted packets. WireGuard/node encryption is separate.

Missing/stale/NACKed policy, trust mismatch, issuer profile expiry, ADS disconnect, permanent map writes require separate deterministic fixture cases. Do not corrupt production issuer approvals or checkpoint files just to manufacture a negative; use an isolated owned test instance or implementation tests. Existing retired `scripts/lab/mtls/bootstrap.sh`/`enable.sh` target cmtc-mtls: DO NOT RUN.

## Invocation order and stop conditions

1. Verify both kube-system UIDs, current sources and images; save existing CM/DS metadata/spec (no Secret payloads); record ownership.
2. Generate Certificates + public RBAC and etcd configuration; wait Ready; verify public cert/current reader path.
3. Prepare per-node pins and private virgin checkpoint directories; generate fresh ADS bootstrap material without printing keys.
4. Complete Cilium config/mounts on A and restart worker then control-plane via sole operational owner. Collect first failure; preserve guards.
5. Render/apply ONLY ztunnel SA+DS, exact image loaded locally; register exact delegate entries; verify new SPIRE credentials/profile checkpoint; remove bootstrap env before restart.
6. Enroll owned fixture, exact workload registration, same-node positive + auth/policy negatives + restart recovery. Record actual selected counts and failures. No zero-selected or skipped proof.
7. Repeat immediately on B; test cross-node and both crosscluster paths, report R7 denials.
8. Repeat affected checks against exact host-Podman rebuilt images and runtime source/image IDs. Preserve current branch/worktrees and unrelated workloads. No CI/registry.

If agent cannot start, inspect source-bound validation/initialization logs, config and mounts. Do not remove required runtime flags. If SPIRE fails, preserve original Admin DAC and use only the delegated socket. If profile lease expires, fail closed and restore valid publication through its existing owner; never lower checkpoint floors. If remote traffic denied, R7 implementation is required under source owner; no operational switch supplies realized remote egress policy.

## Read-only validation receipt

Executed the exact A values block above through `helm template` with the two selected chart templates: exit 0, 6764 rendered characters, correct local image, OnDelete, hostPID/hostNetwork true and ztunnel-cilium SA. No rendered manifest was applied. Public API reads succeeded for ConfigMaps, Services, nodes, CertificateRequests and fixture workload specs. No Secret/private-key content was read. No traffic was generated by this audit.
