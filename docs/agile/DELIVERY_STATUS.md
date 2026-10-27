# End-to-end local delivery status

**Current state, measured by traffic at 2026-10-27T11:14Z.** Both labs run only published images
(`ghcr.io/ephico2real2`). SPIRE's CA on each cluster is issued by `<cluster>-spire-intermediate` under the mesh root,
and approval generation 6 pins that intermediate ([#34](https://github.com/ephico2real2/clustermesh-trust-controller/issues/34)).
Enrolled workload traffic runs over workload mTLS through ztunnel: same node, across nodes and across clusters, by
Pod IP, by per-Pod name and by Global Service name. The matrix at 11:12–11:14Z joined 95 of 96 allowed probes to a
ztunnel mTLS connection by client socket and the 96th by destination and time; Cilium dropped all 36 unregistered
probes. DNS from enrolled Pods was last measured on the 2026-10-26 images (UDP and TCP, in plain text to CoreDNS
only). This is not a `Protected` claim.

**Incident.** Workload mTLS failed closed on both labs from 2026-10-25T23:55Z to 2026-10-26T03:10Z, after a
SPIRE CA rotation that the issuer approval did not pin. The status in this file at 23:56Z said traffic worked; that
was read from readiness, not traffic, and was wrong. See [the incident record](../evidence/issuer-rebootstrap-20261026/INCIDENT.md).

The dated checkpoints that this file held until 2026-10-25T23:56Z are in
[delivery status history](DELIVERY_STATUS_HISTORY_TO_2026-10-25.md), unchanged. They are historical.

## Labs

| Check | cmtc-a | cmtc-b |
| --- | --- | --- |
| Context | `kind-cmtc-a` | `kind-cmtc-b` |
| kube-system UID | `bb7182c7-de95-4e70-816a-a1400d755794` | `f2687af6-bd96-45a3-98a2-d1397a3ee244` |
| Trust domain | `cmtc-a.mesh.example` | `cmtc-b.mesh.example` |
| ClusterMesh (`cilium-dbg status`) | 1/1 remote clusters ready | 1/1 remote clusters ready |
| Agent encryption mode | `Ztunnel` | `Ztunnel` |
| KVStoreMesh | `kvstoremesh` container in `clustermesh-apiserver` | same |
| WireGuard / IPsec | off | off |

Both labs run in Colima profile `cmtc-cilium`. They are the only clusters that qualify a change; see
[AGENTS.md](../../AGENTS.md) for the cluster-first loop. Keep the guest clock stable as described in
[Colima timekeeping](../development/COLIMA_TIMEKEEPING.md).

## Deployed images

Read from the workload image fields at 10:33Z on 2026-10-27, and each image's source labels on the node. Both
clusters run the same digests, and every DaemonSet, Deployment and StatefulSet listed is fully ready.

| Component | Image (`ghcr.io/ephico2real2/…`) | Source |
| --- | --- | --- |
| Cilium agent | `cilium-dev@sha256:c77bdc52d2f3…ac8a447` | Cilium fork `823d30c51b`, branch `feat/ztunnel-tcp-dns-resolvers` |
| Cilium operator | `cilium-dev@sha256:533e8ff5483a…40cb38` | Cilium fork `64a07d46a6` |
| ClusterMesh API server (etcd, apiserver, kvstoremesh) | `cilium-dev@sha256:1e3fc5a8f272…cffc6` | Cilium fork `64a07d46a6` |
| ztunnel | `cmtc-ztunnel@sha256:6f1ae6891782…d4f4f4a` | ztunnel fork `0e92198`, branch `feat/spire-intermediate-pin` |
| SPIRE node agent | `cmtc-spire-agent@sha256:c2d1cbc74d38…a4f1c` | SPIRE fork `0f8fe4d681` |
| SPIRE server | `cmtc-spire-server@sha256:5d125886ba75…986cab` | SPIRE fork `0f8fe4d681` |
| CMTC controller and node agent | `cmtc@sha256:113b94c09da2…e0ac312` | CMTC `5e5d6308f2` |

On 2026-10-27 (10:25–10:32Z) the CMTC, Cilium agent and ztunnel images moved for the SPIRE intermediate
approval, generation 6 ([#34](https://github.com/ephico2real2/clustermesh-trust-controller/issues/34),
[LOCAL_ISSUER_PROFILE.md](../../LOCAL_ISSUER_PROFILE.md#spire-intermediate-mode-issue-34)). They are **deployed and
traffic-qualified** for workload mTLS (the matrix below, 11:12–11:14Z); DNS, recovery and the move under traffic were
not measured on them. The 2026-10-26 images were moved one
component at a time under traffic; see
[the image qualification record](../evidence/image-qualification-20261026/README.md). The SPIRE registrar image is
published but not deployed: making it the live registration owner is the operator's decision.

The labs' ztunnel options exist only as edits to `kube-system/cilium-config`; the Helm release does not hold them, so
a `helm upgrade cilium` would remove them ([#33](https://github.com/ephico2real2/clustermesh-trust-controller/issues/33)).

## Traffic-qualified results

| Result | Evidence |
| --- | --- |
| Matrix after generation 6 and the SPIRE rotation onto the intermediate (2026-10-27, 11:12–11:14Z): 95/96 allowed probes joined per connection by client socket, in every scope; the 96th (HTTP 200 from the expected Pod) joined by destination and time because NAT gave its socket a new source port; 36/36 unregistered probes dropped at `bpf_lxc.c:2381`. | [matrix-g6](../evidence/spire-intermediate-20261027/matrix-g6/README.md) |
| Matrix 7, after the TCP DNS agent (19:05:50–19:07:49Z): 96/96 allowed probes proven per connection (48 by Pod IP, 24 by per-Pod name, each served by its named Pod, 24 by Global Service name); 36/36 unregistered probes dropped at `bpf_lxc.c:2381`. | [matrix 7](../evidence/image-qualification-20261026/matrix-7-tcp-dns/join.txt) |
| DNS from enrolled Pods: UDP 6/6 and TCP 6/6 names per cluster; unenrolled control 2/2; 9/9 negative probes fail per cluster, with TCP 53 to a non-resolver dropped at `bpf_lxc.c:1630`. Before the TCP rule, TCP was 0/6. | [DNS guide](../../MESH_DNS.md), [DNS evidence](../evidence/image-qualification-20261026/dns/) |
| Each component moved to its published image under traffic. Steps 1–3 (CMTC, SPIRE agent, SPIRE server): 0 allowed requests failed. Agent restarts (step 5, TCP DNS step): every failure inside the restart window. | [rollout steps](../evidence/image-qualification-20261026/README.md#rollout-steps) |
| How to repeat the per-connection proof | [Prove mTLS for each request from ztunnel logs](../evidence/g1-destination-sources/PROVE_MTLS_FROM_ZTUNNEL_LOGS.md), `scripts/evidence/run_mtls_matrix.sh` |
| Earlier: mTLS restored on approval generation 2 at 03:10Z; the G1 source-egress record (ADR-010). Historical for the current images. | [Incident record](../evidence/issuer-rebootstrap-20261026/INCIDENT.md#restoration), [G1 traffic record](../evidence/g1-destination-sources/README.md) |

The ADR-010 implementation commits and their test counts are in
[ADR-010, implementation status](../architecture/adr/ADR-010.md#implementation-status-2026-10-25).

## Time limit: issuer approval generation 6 expires at 2026-11-25T10:26:41Z

Both clusters publish from `cmtc-system/cmtc-issuer-approval-g6` (read from the ledger at 11:00Z). The controller
accepts at most 30 days, so a new generation is due before then. `renew_approval.py` publishes it when 7 days remain;
it runs daily at 06:15 local as a launchd agent on the operator's host, installed 2026-10-27T12:03Z; it has not yet
renewed (first renewal due about 2026-11-18)
([LOCAL_ISSUER_PROFILE.md, Approval renewal](../../LOCAL_ISSUER_PROFILE.md#approval-renewal)). SPIRE's own CA
rotations need no new generation. Never reset authority state, floors or the ledger to extend an approval.

## Open gates

1. **Issuer rotation without reset (gate 10).** Both clusters publish generation 6 (2026-10-27), which pins
   `<cluster>-spire-intermediate`, so SPIRE's CA rotations need no new generation. Open: the daily renewal job
   (installed 2026-10-27) reads the kubeconfig from `/private/tmp`, which a host restart clears; the intermediate's own renewal on 2027-09-26 needs an approval that carries both intermediates;
   the rotation report and ADR-012 are not written.
2. **Recovery on the deployed images.** Agent restarts are measured per request above. The ztunnel replacement is
   proven only by the matrix after it (its logs went with the old Pods). Open: node reboot, drain and a lost ACK.
3. **Restored endpoints before quarantine:** for 1–2 s after an agent restart, an unregistered caller on the same node
   reaches the destination's ztunnel, which refuses it ([#31](https://github.com/ephico2real2/clustermesh-trust-controller/issues/31)).
4. **ClusterMesh API server restart** closes cross-cluster traffic for about 65 s
   ([#30](https://github.com/ephico2real2/clustermesh-trust-controller/issues/30)).
5. **ExternalIP on a resolver address** could carry DNS from an enrolled Pod to another backend
   ([#32](https://github.com/ephico2real2/clustermesh-trust-controller/issues/32)).
6. **Cilium configuration persistence** ([#33](https://github.com/ephico2real2/clustermesh-trust-controller/issues/33)).
7. **ADR-010 review findings C2, C3, C4 and C6–C8** (see ADR-010).
8. **Live policy shapes:** a source whose egress denies the destination, and a live port narrowing. Both are
   unit-tested only.
9. **WireGuard/IPsec composition** with workload mTLS.
10. **Monitoring.** CoreDNS exposes `:9153` but is not scraped. Hubble is off. The CMTC eBPF measurement plane
    ([ADR-005](../architecture/adr/ADR-005.md)) is not built beyond Pod inventory. Metrics v2 is uncommitted
    (`observability/v2/`).
11. **Stale material.** `scripts/lab/mtls/bootstrap.sh` still creates the retired `cmtc-mtls` cluster. The
    [component-roles figure](../diagrams/component-roles/source.html) still shows ztunnel activation as pending.

## Approval boundary

The persistent four-node SPIRE agent Admin group-permission migration is **not approved**
(`adminDACMigrationApproved: false` in the lab lease). No migration occurred. The separate DelegatedIdentity-only
listener is the approved path. Preserve agent UID 1000/GID 1000 and its private directory permissions.

## Work in progress and leases

The source/compiler lease (`BUILD_SLOT.json`) and the live-writer lease (`LAB_OWNER.json`) are under
`/private/tmp/cmtc-opus-final-20261025/review/`. Both are owned by Claude Code session `b744973a`. The issuer-rotation
agent's delegation was returned at 18:08:46Z on 2026-10-26.

| Work | Owner | State |
| --- | --- | --- |
| DNS from enrolled Pods (CMTC-603, CMTC-404) | orchestrator | UDP and TCP deployed and traffic-qualified (Cilium `8d7b7accfd`, `a99264f008`) |
| Evidence tools: client-socket join, per-Pod names, DNS probes | orchestrator | committed (`ed6e004`) |
| Issuer rotation without reset (gate 10) | orchestrator | generation 6 published (SPIRE intermediate); renewal job installed (not yet renewed); report and ADR-012 not written |
| eBPF measurement plane review | none | one patch proposed, not applied; no report |
| Metrics, CoreDNS scraping and Grafana dashboards v2 | none | rules and tests pass; not deployed; uncommitted |

Each result is reviewed and verified on both labs before it is committed.

## Authorship and upstream provenance

These are **CMTC-authored additions and modifications in our `ephico2real2` forks**. Name that authorship in feature descriptions, handovers, examples and status reports. Identify the upstream dependency separately. Describe AI implementation and review assistance separately from project authorship.

| Work | Attribution | Source reference |
| --- | --- | --- |
| Remote workload Address projection and per-peer snapshot store | CMTC-authored additions to our Cilium fork | `92ce2b90d3` |
| Effective-policy publication and workload release coordination | CMTC-authored additions to our Cilium fork | `ada009a5f0` |
| ClusterMesh/ztunnel capability validation | CMTC modification to the upstream Cilium startup checks | `37d5fce0f7` |
| Separate DelegatedIdentity-only listener and its isolation | CMTC extension to our SPIRE fork; it uses SPIRE's existing DelegatedIdentity API | SPIRE `0f8fe4d6` |
| Exact workload registrar and its telemetry | CMTC helper and instrumentation using the upstream SPIRE registration API | CMTC `18c47cc` for the metric increment |

Cilium, SPIRE, ztunnel, SPIFFE, Kubernetes and Prometheus remain their respective upstream projects. Reusing their APIs or extending their code does not mean CMTC authored those projects. Preserve upstream attribution and existing source notices.

Git commits use the configured human author `ephico2real2`. Claude Code Opus5.5 supplies implementation assistance; Codex coordinates and independently reviews/validates; Grok supplies adversarial proposals. These roles do not change which project supplied the feature.

Preferred wording: **“CMTC added remote-workload projection and effective-policy release handling to our Cilium fork.”** Then state the exact source commit and its test/deployment limits. Authorship does not establish working end-to-end mTLS or Protected status.

The CMTC-authored source-egress delivery (ADR-010) is Cilium `4849626a2a` through `6090aa6eff`.

## Guides

Read [the backlog](BACKLOG.md), [the security and failure test matrix](../architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md),
[the PKI trust flow](../../PKI_TRUST_FLOW.md), [the local image build](../../LOCAL_IMAGE_BUILD.md) and
[the handover](../handover/CODEX_START_HERE.md).
