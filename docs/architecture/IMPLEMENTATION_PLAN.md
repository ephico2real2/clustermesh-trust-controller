# Incremental implementation and design PR plan

Status: **Proposed**, 2026-10-23. Baseline: [source audit](../research/SOURCE_AUDIT.md). Each PR is independently reviewable; none is a delivery-date commitment. Security-dependent milestones cannot be closed by operator-only work.

User clarification: the primary result is ztunnel workload mTLS over required WireGuard or IPsec node transport, working end to end across ClusterMesh. [Existing lab review](../research/EXISTING_LAB_REVIEW.md) pins the reusable PoC and the adaptations below. This direction does not mark all implementation contracts/ADRs approved.

The user subsequently authorized a first deployable Observe build with CI, copied demo applications and screenshots. That implementation may proceed while enforcement contracts remain under review; the earlier hold on Go/CI/observation-schema scaffolding is superseded for this experimental slice. Live enrollment, Protected status and the encrypted profile retain their security gates. [OBSERVE_LAB.md](../development/OBSERVE_LAB.md) records actual scope and remaining work.

## PR 0 — Import handover and pin the design baseline

Suggested title: `docs: import CMTC handover and audit pinned Cilium interfaces`.

Scope: import the design archive, exact Cilium pin, source-versus-runtime evidence, nine reviewed but unaccepted ADRs, initial threat model, observability gaps and this gated plan. A README-only initial commit provides a base in the empty repository; all design content goes on `design/cilium-source-audit`. Commits use the configured human Git identity and SSH remote.

Acceptance: all archive files accounted for; JSON and internal links checked; manifest refreshed; source citations resolve to the pinned revision and valid line ranges; no CRD/metrics/mTLS implementation claim. Open a draft PR. No deployment, generated CRD, Go scaffold or CI is included. External architecture/security review remains pending.

## PR 1 — Agree the enforcement and identity contracts

Feature F01 / EP01: CMTC-001,002,003; dependencies G01–G07.

Subtasks:

1. Trace ClusterMesh exports through remote identity, ipcache, service and endpoint observers; list missing namespace/service-account/Pod-UID data and who authenticates its origin.
2. Define cluster-qualified xDS keys, expected SPIFFE identity and issuer/cluster verification under the protected common root. Compare cluster-specific trust domains versus an explicitly cluster-bound identity scheme, without selecting one by implication.
3. Trace original TCP tuple/identity through pod iptables, socket-LB and Cilium eBPF, then specify application-port policy preservation and a first-packet gate.
4. Specify external SPIRE attestation/CA endpoint, consumer reload ACK, stale-state behavior and a bounded observation API for CMTC.
5. Define non-enrolled platform paths and a Cilium-enabled OpenShift test profile. Resolve the Cilium ztunnel dependency boundary in ADR-001.

Acceptance: reviewers can follow each security claim to pinned source or a named missing interface; every gap has an owner/component and positive/negative test; all nine ADRs receive explicit architecture/security disposition. Until this gate passes, live enrollment, Go module, CRD generation, CI and enforcement patches stay pending. Approving documentation alone does not prove the datapath.

## PR 2 — Policy evaluation and API contract

F02 / EP02: CMTC-501,502,505,506,507,508; F09 / EP09: CMTC-801. Depends on PR 1 architecture disposition.

Subtasks: choose Go/controller-runtime versions; scaffold module and required CI; design/generate structural CRD schemas; implement a pure selector/classification evaluator and dry-run controller. Require an explicit `AllEligible` or `MatchSelectors` choice; AND inside selectors, OR across selectors, platform protection before exclusions before inclusion. Define singleton/conflicting-policy behavior, empty/invalid selectors, reserved-label RBAC, UID recreation and GitOps field ownership.

Acceptance: table-driven unit/envtest cases cover inclusion, exclusion, platform names/metadata, relabeling, deletion/recreation, conflicting ownership, unauthorized policy/exemption writes and absent platform inventory. Unsupported enforcement returns `Unknown`/`Blocked` with a reason and cannot apply live enrollment labels. `Protected` has no label-only path. Schema validation rejects ambiguous policy modes. A test of desired labels alone cannot close CMTC-503.

## PR 3 — Single-cluster observation and safe enrollment canary

F03 / EP03: CMTC-201..204; F02 / EP02: CMTC-503,504. Depends on approved observation and packet-gate contracts.

Subtasks: controller-runtime cluster controller; lightweight Go DaemonSet for inventory, signed/authenticated generation+digest ACKs and bounded probes. Reuse Cilium's Hive enrollment and ZDS inventory, keeping datapath ownership in Cilium. Compare cost/privilege of a separate agent with a minimal Hive observer; do not copy the reconciler into CMTC. Fresh evidence is bound to node/pod/namespace UID, version, generation and observation time.

Acceptance: missing/stale observations, restart, namespace reuse, node disconnection and mismatched digests never yield `Protected`. A supported single-cluster canary may write labels only after platform interoperability and the first-packet gate pass. No cross-cluster support is advertised. Baseline API/DNS/webhook traffic and existing policy denials survive enable/disable and recovery. If no supported observation interface exists, retain dry-run behavior.

## PR 4 — Option A trust lifecycle spike

F04 / EP04: CMTC-101..105; F03 / EP03: CMTC-203,204. Can follow PR 1 independently of remote datapath work.

Subtasks: pin SPIRE/cert-manager/trust-manager and issuer implementation; reuse Cilium SPIRE namespace/service-account enrollment; prove ztunnel credential delivery; define intermediate hierarchy and cluster identity constraints; distribute only public bundles; implement staged rotation with actual SPIRE/ztunnel reload evidence. Distinguish routine rotation from emergency compromise.

Acceptance: protected root key never enters cluster/node/namespace secrets; unauthorized cluster identity CSRs fail even with a common root; old+new bundles are consumed everywhere before issuance changes; partitions/stale ACKs block retirement; drain includes live connections and old SVID expiry; restart and compromise playbooks are exercised. Secret/ConfigMap existence cannot count as consumer ACK.

## PR 5a/5b — Upstream native cross-cluster mTLS and authorization

F05 / EP05: CMTC-401..404; F09 / EP09: CMTC-805 for upstream proposal planning. Depends on PR 1; runtime proof also needs PR 4.

Subtasks: follow the [Cilium integration contract](CILIUM_ZTUNNEL_CONTRACT.md): authenticated remote workload discovery/lifecycle, cluster identity spike, then effective Cilium L4 policy translation and fail-closed traffic admission. The [Istio/Linkerd source comparison](../research/MESH_MTLS_COMPARISON.md) finds an existing proxy authorization engine, missing-reference allow behavior, same-trust-domain verification and protocol differences that may require explicit Rust proxy changes alongside Go/Hive patches. Document datapath changes separately. Send an upstream proposal only when explicitly authorized; local design does not send maintainer messages.

Acceptance: two pinned clusters pass pod-IP and Global Service tests, with matching namespace/service-account names in different clusters. Wrong cluster, unknown/stale identity, unauthorized application port, excluded→protected traffic, pod creation/relabel races, SPIRE outage, ztunnel crash, Cilium restart and cache resync all have denial/capture evidence. Keep the incompatibility guard for configurations without these capabilities. Remove/narrow it only with corresponding security tests; successful TLS alone cannot close CMTC-403.

## PR 6 — Independent transport composition

F06 / EP06: CMTC-301..305. Depends on the secure HBONE baseline; trace spikes may start after PR 1.

Subtasks: separate workload-authentication and transport settings; capability negotiation rejects unsupported/mixed combinations. Trace WireGuard/XFRM/eBPF marks and identity through overlay/direct routing, MTU/MSS, service translation and key rotation.

Start composition qualification with WireGuard using the existing lab's measured WG exercise; then add IPsec as a separate profile. Preserve the user's existing Cilium Hubble patch on its own branch. The lab uses a 1.20.2-derived agent; review/cherry-pick applicable changes into an isolated branch against the selected CMTC pin rather than replacing the existing lab branch.

Acceptance: for none/WireGuard/IPsec with mTLS off, baseline ClusterMesh regression tests pass on supported profiles. With mTLS on, TLS peer identity/policy evidence and independent WG/XFRM state plus packet captures establish both required layers. Missing keys, stale XFRM, node reboot and MTU failure produce no required-layer downgrade. No unsupported combination silently coerces to another mode.

## PR 7 — Platform, observability and release qualification

F07 / EP07: CMTC-601..606; F08 / EP08: CMTC-701..706; F09 / EP09: CMTC-802..805. Metrics contracts start earlier; release claims wait for full evidence.

Subtasks: Kubernetes/OpenShift/hosted-control-plane inventory and SCC/RBAC profile; progressive rollout and verified rollback; real exporters, metric fixtures, recording/alert rules, nine dashboard imports, packaging and runbooks. Reuse native collectors only after actual scrape verification.

CMTC-802 should derive its small two-cluster topology and evidence-before-teardown pattern from the pinned PoC. Adapt the root-copy bootstrap to protected root/cluster intermediates, pin agent/proxy/CRD inputs immutably, make required connectivity/security checks mandatory and convert evidence-printing checks into failing assertions. Establish the core encrypted path before adding the full observability stack.

Acceptance: API, DNS UDP/TCP, webhooks, kubelet, ingress, OAuth, operators, etcd, bootstrap/recovery and upgrades remain healthy. Failure stops rollout; rollback requires datapath and platform recovery, not label removal. Promtool rule checks/tests and Grafana imports cover success, denial, zero traffic, absent exporter and missing cluster series. Security-negative, resilience and performance suites pass the pinned version matrix before production support is stated.

## Tracking and completion

Canonical hierarchy: initiative → F01..F09 → EP01..EP09 → CMTC story → listed subtasks. [stories.csv](../agile/stories.csv) retains the existing 46 story IDs. PR 0 records static review only; CMTC-001 stays in review while deep datapath traces remain, CMTC-002 is an initial threat-model draft, and CMTC-003 awaits explicit approval. Stories are closed by their acceptance evidence, not by a dashboard or desired label.
