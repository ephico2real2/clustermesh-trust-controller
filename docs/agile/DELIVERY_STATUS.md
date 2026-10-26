# End-to-end local delivery status

**Current state, measured by traffic at 2026-10-26T03:10Z.** Enrolled workload traffic runs over workload mTLS
through ztunnel: same node, across nodes and across clusters, in both directions. All 48 allowed Pod-IP probes are
joined to a ztunnel HBONE connection that both ztunnels logged, with the client identity read from its certificate.
All 12 unregistered callers were dropped by Cilium. DNS from enrolled Pods fails, so the Global Service by name fails.
Recovery is not yet tested on the deployed images. This is not a `Protected` claim.

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

Read from the workload image fields at 23:56Z. Both clusters run the same images. Every DaemonSet and Deployment in
both clusters is fully ready.

| Component | Image | Source |
| --- | --- | --- |
| Cilium agent | `localhost/cilium:dev-overlay-6090aa6eff` | Cilium fork `6090aa6eff`, branch `feat/opus-mesh-mtls-finalization` |
| Cilium operator, ClusterMesh API server | `dev-overlay-0ed63bf906` | Cilium fork `0ed63bf906` |
| ztunnel | `localhost/cmtc-ztunnel@sha256:5cf97f91e562…` (tag `native-f221f29b59`) | ztunnel fork `f221f29b59`, branch `feat/opus-mesh-mtls-finalization` |
| SPIRE node agent | `localhost/cmtc-spire-agent:delegated-0f8fe4d681` | SPIRE fork `0f8fe4d6` |
| SPIRE server | `localhost/cmtc-spire-server@sha256:f57e537d42e5…` | not re-verified in this checkpoint |
| CMTC controller and node agent | `localhost/cmtc:current-46d01e91ce` | CMTC `46d01e9` |

The Cilium and ztunnel source commits are pushed to `ephico2real2/cilium` and `ephico2real2/ztunnel`. SPIRE
`0f8fe4d6` is on the fork's `main`. No fork CI ran, and no image is published to a registry.

## Traffic-qualified results

| Result | Evidence |
| --- | --- |
| mTLS restored on the generation-2 approval (03:09:41–03:10:29Z): 48/48 allowed Pod-IP probes proven per connection; 12/12 unregistered callers dropped at `bpf_lxc.c:2373`; 0 ztunnel errors or warnings. | [Incident record, restoration](../evidence/issuer-rebootstrap-20261026/INCIDENT.md#restoration) |
| Source egress delivered to the destination (ADR-010). 48/48 allowed Pod-IP probes are joined to a ztunnel connection that both ztunnels logged, over HBONE port 15008, with the expected client SPIFFE ID read from the client certificate. The 12 connections of the Global Service check by ClusterIP have the same properties. 12/12 unregistered callers got no response and no ztunnel logged them. | [G1 traffic record](../evidence/g1-destination-sources/README.md) |
| How to repeat the per-connection proof | [Prove mTLS for each request from ztunnel logs](../evidence/g1-destination-sources/PROVE_MTLS_FROM_ZTUNNEL_LOGS.md) |
| Earlier images (agent `bc2c9639c5`): ZDS ownership fixes rolled out and the agent `hostPID` requirement removed. Historical for the current images. | [ZDS ownership rollout](../evidence/zds-ownership-rollout-20261025/README.md) |

The ADR-010 implementation commits and their test counts are in
[ADR-010, implementation status](../architecture/adr/ADR-010.md#implementation-status-2026-10-25).

## Time limit: SPIRE activates its next CA at about 2026-10-26T11:55Z

Both clusters publish from `cmtc-system/cmtc-issuer-approval-g2` (generation 2). It pins SPIRE's current CA (slot B)
and expires at `2026-10-26T15:55:19Z`. SPIRE prepares its next CA at about 03:55Z and activates it at about 11:55Z.
From then on, ztunnel refuses every handshake again, until the approval also holds the new CA. A rotation
that needs no checkpoint reset is in progress (gate 10). The operator authorized one reset only, and it is used. Never
reset authority state, floors or the ledger to extend the approval.

## Open gates

1. **DNS from enrolled Pods.** The HBONE-only gate in `bpf/lib/ztunnel_admission.h` passes only TCP/15008, so the
   source endpoint drops the DNS query (`bpf_lxc.c:1626`). Cilium fork commit `8d7b7accfd` admits UDP and TCP port
   53 only to approved resolver identities. It is tested offline only and not deployed; see `review/dns-fix/REPORT.md`.
2. **Recovery on the deployed images:** agent restart with an open cross-cluster connection, ztunnel restart, node
   reboot, drain and a lost ACK.
3. **ADR-010 review findings C2, C3, C4 and C6–C8** (see ADR-010).
4. **Live policy shapes:** a source whose egress denies the destination, and a live port narrowing. Both are
   unit-tested only.
5. **Native drop events** for the negative probes. The 03:10Z run attributes all 12 to Cilium
   (`Policy denied at bpf_lxc.c:2373`) with the drop capture. The evidence tools that do this are not committed yet.
6. **24 client-side HBONE handshake errors** (`authenticated issuer profile/session expired or changed`) between
   23:01:54Z and 23:12:22Z on 2026-10-25. No probe failed because of them. The cause is not diagnosed. The 03:10Z run
   logged 0 errors or warnings.
7. **WireGuard/IPsec composition** with workload mTLS.
8. **Monitoring.** CoreDNS exposes `:9153` but is not scraped. The `cilium-native` scrape keeps only
   `cilium_ztunnel_.*|cmtc_.*`. Hubble is off. The CMTC eBPF measurement plane ([ADR-005](../architecture/adr/ADR-005.md))
   is not built beyond Pod inventory: `internal/agent/` holds only `inventory.go`.
9. **Stale material.** `scripts/lab/mtls/bootstrap.sh` still creates the retired `cmtc-mtls` cluster. The
   [component-roles figure](../diagrams/component-roles/source.html) still shows ztunnel activation as pending.
10. **Issuer rotation without reset.** Source succession that carries the checkpoint floors, and SPIRE's prepared CA
    as the second approved issuer. It must be qualified on both labs before about 11:55Z.

## Approval boundary

The persistent four-node SPIRE agent Admin group-permission migration is **not approved**
(`adminDACMigrationApproved: false` in the lab lease). No migration occurred. The separate DelegatedIdentity-only
listener is the approved path. Preserve agent UID 1000/GID 1000 and its private directory permissions.

## Work in progress and leases

The source/compiler lease (`BUILD_SLOT.json`) and the live-writer lease (`LAB_OWNER.json`) are under
`/private/tmp/cmtc-opus-final-20261025/review/`. Both are owned by Claude Code session `b744973a` and delegated to the
issuer-rotation agent: the compiler lease at 02:38Z and the live-writer lease at 03:15Z on 2026-10-26. Nothing else
compiles or writes to the labs until it hands back.

| Work | Owner | State |
| --- | --- | --- |
| Issuer rotation without reset (gate 10) | issuer-rotation agent, holds both leases | in progress; brief `review/issuer-rotation/BRIEF.md` |
| DNS resolver exception (gate 1) | orchestrator | committed in the Cilium fork (`8d7b7accfd`), tested offline; deploy waits for the lease |
| Cilium drop attribution and DNS verdicts in the evidence tools (gate 5) | orchestrator | finished; uncommitted in `scripts/evidence/` |
| eBPF measurement plane review (gate 8) | eBPF review agent, read-only | restarted at 02:58Z after the 00:16Z stop |
| Metrics, CoreDNS scraping and Grafana dashboards v2 (gate 8) | metrics review agent, read-only | restarted at 02:58Z; partial inventory kept; uncommitted `observability/v2/` |

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
