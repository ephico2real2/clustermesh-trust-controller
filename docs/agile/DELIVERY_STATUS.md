# End-to-end local delivery status

**Current state, measured by traffic at 2026-10-27T11:14Z.** Both labs run only published images
(`ghcr.io/ephico2real2`). SPIRE's CA on each cluster is issued by `<cluster>-spire-intermediate` under the mesh root,
and approval generation 6 pins that intermediate ([#34](https://github.com/ephico2real2/clustermesh-trust-controller/issues/34)).
Enrolled workload traffic runs over workload mTLS through ztunnel: same node, across nodes and across clusters, by
Pod IP, by per-Pod name and by Global Service name. The matrix at 11:12–11:14Z joined 95 of 96 allowed probes to a
ztunnel mTLS connection by client socket and the 96th by destination and time; Cilium dropped all 36 unregistered
probes. DNS from enrolled Pods was last measured on the 2026-10-26 images (UDP and TCP, in plain text to CoreDNS
only). This is not a `Protected` claim.

**Update 2026-10-27T17:05Z.** cert-manager's built-in approver approves every request on both labs (operator decision;
approver-policy removed, [MESH_PKI.md, Approval](../../MESH_PKI.md#approval)). Cilium on cmtc-b is adopted into Helm
(#33), and both clusters render equal to live at release revision 8. Hubble runs on every agent with TLS from the mesh
PKI; one Relay and the UI in cmtc-a see 4/4 nodes; Hubble and ztunnel metrics are scraped
([Hubble evidence](../evidence/hubble-20261027/README.md)). The matrix after these changes: 96/96 allowed probes
proven over mTLS, 36/36 unregistered probes dropped.

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

Read from the workload image fields at 19:25:42Z on 2026-10-27; the CMTC row at 20:00:46Z. Both clusters run the same
digests, and every DaemonSet, Deployment and StatefulSet listed is fully ready.

| Component | Image (`ghcr.io/ephico2real2/…`) | Source |
| --- | --- | --- |
| Cilium agent | `cilium-dev@sha256:8446cf910bdb…69b2cc` (cmtc-b Helm revision 12, 2026-10-28 16:26Z; cmtc-a revision 11, 17:23Z) | Cilium fork `ce5c3ec031`, branch `fix/ztunnel-origin-credential-renewal` ([cmtc-b record](../evidence/cert-rotation-drills-20261028/README.md), [cmtc-a and the server leaf expiry](../evidence/cert-rotation-drills-20261028/server-leaf-expiry/README.md)). Known defect: the agent loads its ztunnel ADS server certificate once at start (fix `c84f7d0741`, not deployed); the in-memory certificates expire 2026-10-29 11:17Z |
| Cilium operator | `cilium-dev@sha256:533e8ff5483a…40cb38` | Cilium fork `64a07d46a6` |
| ClusterMesh API server (etcd, apiserver, kvstoremesh) | `cilium-dev@sha256:1e3fc5a8f272…cffc6` | Cilium fork `64a07d46a6` |
| Hubble relay (cmtc-a only) | `cilium-dev@sha256:bbda6e67ddb9…6b0413` | Cilium fork `b1c3622a9a` ([record](../evidence/hubble-20261027/README.md)) |
| ztunnel | `cmtc-ztunnel@sha256:bc4fb925ae90…c87771` | ztunnel fork `68c0282`, branch `feat/root-pin-retirement` (draft PR ephico2real2/ztunnel#2) |
| SPIRE node agent | `cmtc-spire-agent@sha256:c2d1cbc74d38…a4f1c` | SPIRE fork `0f8fe4d681` |
| SPIRE server | `cmtc-spire-server@sha256:5d125886ba75…986cab` | SPIRE fork `0f8fe4d681` |
| CMTC controller and node agent | `cmtc@sha256:a99717bbba66…38cbd1` | CMTC `9145ad0` (CI run 40580338929; from 2026-10-27T20:48Z); Helm release `cmtc` (cmtc-a revision 3, cmtc-b revision 2), issuer approval arbiter on; `config/lab/cmtc/values-<cluster>.yaml` pins the digest (render equals live, 2026-10-28) |

On 2026-10-27 (10:25–10:32Z) the CMTC, Cilium agent and ztunnel images moved for the SPIRE intermediate
approval, generation 6 ([#34](https://github.com/ephico2real2/clustermesh-trust-controller/issues/34),
[LOCAL_ISSUER_PROFILE.md](../../LOCAL_ISSUER_PROFILE.md#spire-intermediate-mode-issue-34)). They are **deployed and
traffic-qualified** for workload mTLS (the matrix below, 11:12–11:14Z); DNS, recovery and the move under traffic were
not measured on them. The 2026-10-26 images were moved one
component at a time under traffic; see
[the image qualification record](../evidence/image-qualification-20261026/README.md). The SPIRE registrar image is
published but not deployed: making it the live registration owner is the operator's decision.

On 2026-10-27 (19:05–19:21Z) the ztunnel image moved to `68c0282`, and the retired Lab Organization Root was removed
from every node's ztunnel issuer pins without a checkpoint reset; **deployed and traffic-qualified** (96/96, 36/36;
[record](../evidence/root-pin-retirement-20261027/README.md)).

The Cilium releases hold the labs' ztunnel options since the Helm adoption of 2026-10-27
([#33](https://github.com/ephico2real2/clustermesh-trust-controller/issues/33),
[cmtc-b record](../evidence/helm-adoption-cmtc-b-20261027/README.md)); `cilium_release.py check` shows 0 differences
on both clusters at 19:14Z (cmtc-a revision 9) and 19:05Z (cmtc-b revision 10).

## Traffic-qualified results

| Result | Evidence |
| --- | --- |
| Matrix after Hubble on both clusters and the cmtc-b Helm adoption (2026-10-27, 16:57Z): 96/96 allowed probes proven over mTLS, 36/36 unregistered probes dropped, 0 failed. The same result at 16:47Z after the adoption alone. | [Hubble](../evidence/hubble-20261027/README.md), [cmtc-b adoption](../evidence/helm-adoption-cmtc-b-20261027/README.md) |
| Matrix after generation 6 and the SPIRE rotation onto the intermediate (2026-10-27, 11:12–11:14Z): 95/96 allowed probes joined per connection by client socket, in every scope; the 96th (HTTP 200 from the expected Pod) joined by destination and time because NAT gave its socket a new source port; 36/36 unregistered probes dropped at `bpf_lxc.c:2381`. | [matrix-g6](../evidence/spire-intermediate-20261027/matrix-g6/README.md) |
| Matrix 7, after the TCP DNS agent (19:05:50–19:07:49Z): 96/96 allowed probes proven per connection (48 by Pod IP, 24 by per-Pod name, each served by its named Pod, 24 by Global Service name); 36/36 unregistered probes dropped at `bpf_lxc.c:2381`. | [matrix 7](../evidence/image-qualification-20261026/matrix-7-tcp-dns/join.txt) |
| DNS from enrolled Pods: UDP 6/6 and TCP 6/6 names per cluster; unenrolled control 2/2; 9/9 negative probes fail per cluster, with TCP 53 to a non-resolver dropped at `bpf_lxc.c:1630`. Before the TCP rule, TCP was 0/6. | [DNS guide](../../MESH_DNS.md), [DNS evidence](../evidence/image-qualification-20261026/dns/) |
| Each component moved to its published image under traffic. Steps 1–3 (CMTC, SPIRE agent, SPIRE server): 0 allowed requests failed. Agent restarts (step 5, TCP DNS step): every failure inside the restart window. | [rollout steps](../evidence/image-qualification-20261026/README.md#rollout-steps) |
| Cilium Ingress in shared mode on both clusters (2026-10-28; cmtc-a Helm revision 10 at 04:17Z, cmtc-b revision 11 at 07:40Z): one LB IPAM address per cluster (172.18.250.10, 172.18.251.10), announced on the kind network (L2), no node port; `*.cmtc-<x>.localtest.me` names from `charts/cmtc-lab-network`. No Pod template change; operator and agents restarted one at a time. Matrix on each cluster afterwards: 96/96 allowed probes proven over mTLS, 36/36 unregistered probes dropped, 0 failed. | [Cilium Ingress](../evidence/cilium-ingress-20261028/README.md) |
| Origin session renewal at the peer server certificate's end (2026-10-28, 1-hour ClusterMesh server leaves): all four agents refreshed in place 10 minutes before the leaf's NotAfter (18:00:02-18:00:04Z, 2.3-4.4 ms); 5,727 allowed probes on both clusters, 0 failed; 0 withdrawals. The same test caused a 12-minute outage on cmtc-a (17:11:55-17:23:47Z) from the ADS certificate defect | [server leaf expiry](../evidence/cert-rotation-drills-20261028/server-leaf-expiry/README.md) |
| How to repeat the per-connection proof | [Prove mTLS for each request from ztunnel logs](../evidence/g1-destination-sources/PROVE_MTLS_FROM_ZTUNNEL_LOGS.md), `scripts/evidence/run_mtls_matrix.sh` |
| Earlier: mTLS restored on approval generation 2 at 03:10Z; the G1 source-egress record (ADR-010). Historical for the current images. | [Incident record](../evidence/issuer-rebootstrap-20261026/INCIDENT.md#restoration), [G1 traffic record](../evidence/g1-destination-sources/README.md) |

The ADR-010 implementation commits and their test counts are in
[ADR-010, implementation status](../architecture/adr/ADR-010.md#implementation-status-2026-10-25).

## Issuer approval: generation 7, written by the arbiter

The issuer approval arbiter ([ADR-012](../architecture/adr/ADR-012.md)) is **deployed** on both labs and its adoption
is **traffic-qualified** ([record](../evidence/approval-arbiter-20261027/README.md)). It adopted g6 on each cluster as
generation 7 with the same issuers, in `cmtc-system/cmtc-issuer-approval-a` (cmtc-b 19:47:28Z, expires
2026-11-25T19:47:11Z; cmtc-a 19:56:10Z, expires 2026-11-25T19:55:52Z). Both publications are `published 7`; every
node accepts generation 7; matrix 96/96 proven, 36/36 dropped (19:56–20:00Z). The arbiter renews 168 h before expiry
(first due about 2026-11-18T19:47Z). Never reset authority state, floors or the ledger to extend an approval.

- **Step 6, forced renewal of cmtc-b's intermediate (in progress):** both arbiters wrote generation 8 with both cmtc-b
  keys (20:03-20:04Z); both clusters `Overlapping`, matrix 96/96. Open: SPIRE's next CA under the new key (activation
  about 2026-10-28T06:52Z) and the retirement of the old key, generation 9 (about 2026-10-28T21:03Z).
- **Step 7, recovery (cmtc-b):** a controller restart and a node agent restart changed nothing approved, 0 fences.
  The peer-unreachable test found a defect: after a controller restart each pass waited 30 s in API discovery and
  could not write its status, so the record kept a stale `EvidenceReady=True` (nothing was approved). Fixed in
  `ca56da7` (4 s peer request timeout; the status write outside the pass deadline), deployed on both labs; the rerun
  reported `EvidenceMissing` in the first pass, every pass ended in 4.0-4.2 s, matrix 96/96 during and after.

## Open gates

1. **Issuer rotation without reset (gate 10).** Both clusters publish generation 6 (2026-10-27), which pins
   `<cluster>-spire-intermediate`, so SPIRE's CA rotations need no new generation. Open: the approval must follow
   cert-manager in the cluster (renewal before expiry, and the intermediate's key rotation on 2027-09-26 with an
   overlap of both intermediates); in design;
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
10. **Monitoring.** The CMTC eBPF measurement plane ([ADR-005](../architecture/adr/ADR-005.md)) is not built beyond
    Pod inventory. Observability v2 (`observability/v2/`) is deployed but not traffic-qualified: no dashboard is
    checked under load in both themes.
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
| Issuer rotation without reset (gate 10) | orchestrator | generation 6 published (SPIRE intermediate); approval renewal in design (no host job); report and ADR-012 not written |
| eBPF measurement plane review | none | one patch proposed, not applied; no report |
| Observability v2: metrics contract, rules, Grafana dashboards, chart `cmtc-observability` (#37) | orchestrator | deployed as Helm release `cmtc-obs` (namespace `monitoring`, revision 2, 2026-10-28T07:23Z): hub on kind-cmtc-a behind Cilium Ingress, member on kind-cmtc-b remote-writing to it; 17/16 targets up at 17:03Z; 69 tests pass with promtool; render equals live on cmtc-b, and on cmtc-a differs only by the panel markers and one rule comment that the next upgrade applies (not run); not traffic-qualified ([chart README](../../observability/v2/deploy/chart/README.md)) |
| Certificate renewal without a failed connection (#47 P1-P3, #46) | Fable, Phase 1 done | Cilium fork `ce5c3ec031` (branch `fix/ztunnel-origin-credential-renewal`): implemented and unit-tested with `-race`, agent image `cilium-dev@sha256:8446cf910bdb…69b2cc` deployed on cmtc-b (revision 12) with drills R1-R4 at 0 failed probes, not yet on cmtc-a; drill `scripts/evidence/rotation_drill.py` dry-run; [design note](../architecture/MESH_CERTIFICATE_RENEWAL.md); Phase 2 (Helm rollout and drills) awaits the orchestrator |

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
