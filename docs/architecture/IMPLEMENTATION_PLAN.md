# Incremental implementation and design PR plan

<!-- CMTC_DOC_CONTEXT -->
Design scope: proposed behavior requires the stated acceptance tests. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This page preserves the original PR plan from 2026-10-23.
Its PR numbers describe the planning sequence; they do not report current completion.
Security acceptance criteria remain binding where their implementation is incomplete.
Use [delivery status](../agile/DELIVERY_STATUS.md) and the backlog for the first unfinished dependency.

The primary target remains ztunnel workload mTLS over WireGuard or IPsec across ClusterMesh.
The [lab review](../research/EXISTING_LAB_REVIEW.md) records the historical PoC baseline.
Architecture and security approval remain separate from source tests and runtime evidence.

The user authorized Observe builds, Go/API scaffolding, deployment, applications, and screenshots after the initial planning phase.
That initial scaffolding hold is superseded.
The active mandate authorizes continued end-to-end implementation with local qualification.
Current instructions defer CI, branch pushes, and image publication.
Do not restart an initial authorization gate for work already authorized.
Production enrollment and `Protected` claims still require their security acceptance tests.

## Current state — 2026-10-25

| PR | State |
| --- | --- |
| PR 3: observation and safe canary | The node agent DaemonSet is deployed (unprivileged). The eBPF measurement plane is decided ([ADR-005](adr/ADR-005.md), Proposed) and not built; the single-workload observer and the fence are in source and not deployed. |
| PR 4: trust lifecycle | Separate cluster CAs, exact SPIRE signers and per-cluster trust domains are deployed. Rotation is not run. Registration owner undecided. |
| PR 5a/5b: native cross-cluster mTLS | Implemented in our Cilium and ztunnel forks and deployed. Allow paths pass in both directions ([test matrix](SECURITY_AND_FAILURE_TEST_MATRIX.md)). The blanket ClusterMesh/ztunnel rejection is replaced by a capability check. Recovery, policy-deny shapes, DNS from enrolled Pods and the [ADR-010](adr/ADR-010.md) review findings remain open. |
| PR 6: transport composition | Not started. WireGuard and IPsec are not configured. |
| PR 7: platform and observability | Two v1 dashboard pages are current; `observability/v2/` is in progress. |

Pins: [delivery status](../agile/DELIVERY_STATUS.md). No workload is `Protected`.

See [SPIRE registration design](../../SPIRE_REGISTRATION_DESIGN.md) for the registrar alternatives and exact authority boundaries.
Source test success does not close runtime registration, credential withdrawal, traffic, policy, or existing-flow revocation gates.

## Original PR sequence

The sections below retain the original design trace.
Historical setup tasks do not imply an empty repository or a current deployment instruction.
Do not dispatch CI or publish from this plan while the current deferral applies.

## PR 0 — Import handover and pin the design baseline

Historical suggested title: `docs: import CMTC handover and audit pinned Cilium interfaces`.

Historical scope: import the design archive, exact Cilium pin, source/runtime evidence, proposed ADRs, threat model, and plan. The initial README and design branch provided the original repository base. Preserve that history. Use the configured human Git identity for qualified increments.

Historical acceptance: account for archive files and validate JSON, links, manifests, and pinned source citations. The documentation import did not establish an implemented CRD, metrics, or mTLS capability. Its original PR step does not authorize a new publication. Architecture and security disposition remain explicit.

## PR 1 — Agree the enforcement and identity contracts

Feature F01 / EP01: CMTC-001,002,003; dependencies G01–G07.

Subtasks:

1. Trace ClusterMesh exports through remote identity, ipcache, service and endpoint observers; list missing namespace/service-account/Pod-UID data and who authenticates its origin.
2. Define cluster-qualified xDS keys, expected SPIFFE identity and issuer/cluster verification under the protected common root. Compare cluster-specific trust domains versus an explicitly cluster-bound identity scheme, without selecting one by implication.
3. Trace original TCP tuple/identity through pod iptables, socket-LB and Cilium eBPF, then specify application-port policy preservation and a first-packet gate.
4. Specify external SPIRE attestation/CA endpoint, consumer reload ACK, stale-state behavior and a bounded observation API for CMTC.
5. Define non-enrolled platform paths and a Cilium-enabled OpenShift test profile. Resolve the Cilium ztunnel dependency boundary in ADR-001.

Acceptance: trace each security claim to pinned source or a named missing interface. Give each gap an owner and positive/negative tests. Record explicit ADR dispositions. The original Go/API scaffolding hold is superseded by later implementation authorization. Live production enrollment and protection claims retain their specific security gates. Documentation approval does not prove the datapath.

## PR 2 — Policy evaluation and API contract

F02 / EP02: CMTC-501,502,505,506,507,508; F09 / EP09: CMTC-801. Depends on PR 1 architecture disposition.

Original subtasks: choose Go/controller-runtime versions; create the module, CI, CRD schemas, evaluator, and dry-run controller. These are historical setup tasks; inspect existing implementation before planning changes. Current CI execution remains deferred. Require an explicit `AllEligible` or `MatchSelectors` choice; AND inside selectors, OR across selectors, platform protection before exclusions before inclusion. Define singleton/conflicting-policy behavior, empty/invalid selectors, reserved-label RBAC, UID recreation and GitOps field ownership.

Acceptance: table-driven unit/envtest cases cover inclusion, exclusion, platform names/metadata, relabeling, deletion/recreation, conflicting ownership, unauthorized policy/exemption writes and absent platform inventory. Unsupported enforcement returns `Unknown`/`Blocked` with a reason and cannot apply live enrollment labels. `Protected` has no label-only path. Schema validation rejects ambiguous policy modes. A test of desired labels alone cannot close CMTC-503.

## PR 3 — Single-cluster observation and safe enrollment canary

F03 / EP03: CMTC-201..204; F02 / EP02: CMTC-503,504. Depends on approved observation and packet-gate contracts.

Subtasks: maintain the controller-runtime cluster controller and Go DaemonSet inventory, authenticated generation/digest ACKs, and bounded probes. The DaemonSet's eBPF programs are the permanent, observe-only per-node measurement plane ([ADR-005](adr/ADR-005.md), operator mandate 2026-10-25); the production quarantine gate is native in the enhanced Cilium agent. The measurement plane preserves Cilium policy and service translation and never decides a verdict. Reuse Cilium's Hive enrollment and ZDS inventory; do not copy the reconciler into CMTC. Fresh evidence is bound to node/pod/namespace UID, version, generation and observation time.

Acceptance: missing/stale observations, restart, namespace reuse, node disconnection and mismatched digests never yield `Protected`. The measurement plane has explicit hook-mode compatibility, a proven pass verdict on every program path, map/interface ownership, attach/detach, Cilium reload and recovery evidence before any canary. A supported single-cluster canary may write labels only after platform interoperability and the first-packet gate pass. No cross-cluster support is advertised. Baseline API/DNS/webhook traffic and existing policy denials survive enable/disable and recovery. Native or ClusterMesh support is claimed only from the native Cilium gate and the live matrix, never from measurement-plane data. A measurement hook that cannot be attached safely reports unavailable and is left out.

## PR 4 — Option A trust lifecycle spike

F04 / EP04: CMTC-101..105; F03 / EP03: CMTC-203,204. Can follow PR 1 independently of remote datapath work.

Subtasks: pin SPIRE, cert-manager, trust-manager, and the issuer implementation.
Reuse Cilium SPIRE namespace/service-account enrollment.
Prove ztunnel credential delivery.
Define the intermediate hierarchy and cluster identity constraints.
Distribute only public bundles.
Test staged rotation with actual SPIRE and ztunnel reload evidence.
Keep routine rotation separate from emergency compromise.

Later experimental change: a separate CMTC registrar now tests exact, expiring registrations inside the SPIRE server Pod.
That image is not an approved replacement for the original Cilium reuse baseline.
Record the production owner decision and migration tests before adopting it.
Keep server Admin access separate from the pending node agent Admin permission change.
See [SPIRE registration design](../../SPIRE_REGISTRATION_DESIGN.md).

Acceptance: protected root key never enters cluster/node/namespace secrets; unauthorized cluster identity CSRs fail even with a common root; old+new bundles are consumed everywhere before issuance changes; partitions/stale ACKs block retirement; drain includes live connections and old SVID expiry; restart and compromise playbooks are exercised. Secret/ConfigMap existence cannot count as consumer ACK.

## PR 5a/5b — Upstream native cross-cluster mTLS and authorization

F05 / EP05: CMTC-401..404; F09 / EP09: CMTC-805 for upstream proposal planning. Depends on PR 1; runtime proof also needs PR 4.

Subtasks: follow the [Cilium integration contract](CILIUM_ZTUNNEL_CONTRACT.md): authenticated remote workload discovery/lifecycle, cluster identity spike, then effective Cilium L4 policy translation and fail-closed traffic admission. The [Istio/Linkerd source comparison](../research/MESH_MTLS_COMPARISON.md) finds an existing proxy authorization engine, missing-reference allow behavior, same-trust-domain verification and protocol differences that may require explicit Rust proxy changes alongside Go/Hive patches. Document datapath changes separately. Send an upstream proposal only when explicitly authorized; local design does not send maintainer messages.

Acceptance: two pinned clusters pass pod-IP and Global Service tests, with matching namespace/service-account names in different clusters. Wrong cluster, unknown/stale identity, unauthorized application port, excluded→protected traffic, pod creation/relabel races, SPIRE outage, ztunnel crash, Cilium restart and cache resync all have denial/capture evidence. Keep the incompatibility guard for configurations without these capabilities. Remove/narrow it only with corresponding security tests; successful TLS alone cannot close CMTC-403. (2026-10-25: the guard is narrowed to a capability check in our Cilium fork, `pkg/ztunnel/cell.go:73`; the denial and recovery tests above are still open.)

## PR 6 — Independent transport composition

F06 / EP06: CMTC-301..305. Depends on the secure HBONE baseline; trace spikes may start after PR 1.

Subtasks: separate workload-authentication and transport settings; capability negotiation rejects unsupported/mixed combinations. Trace WireGuard/XFRM/eBPF marks and identity through overlay/direct routing, MTU/MSS, service translation and key rotation.

Start composition qualification with WireGuard using the existing lab's measured WG exercise; then add IPsec as a separate profile. Preserve the user's existing Cilium Hubble patch on its own branch. The original PoC used a 1.20.2-derived agent. That pin is historical. Use the pins in delivery status and preserve the user's existing lab and Hubble work.

Acceptance: for none/WireGuard/IPsec with mTLS off, baseline ClusterMesh regression tests pass on supported profiles. With mTLS on, TLS peer identity/policy evidence and independent WG/XFRM state plus packet captures establish both required layers. Missing keys, stale XFRM, node reboot and MTU failure produce no required-layer downgrade. No unsupported combination silently coerces to another mode.

## PR 7 — Platform, observability and release qualification

F07 / EP07: CMTC-601..606; F08 / EP08: CMTC-701..706; F09 / EP09: CMTC-802..805. Metrics contracts start earlier; release claims wait for full evidence.

Subtasks: maintain Kubernetes, OpenShift, and hosted-control-plane inventory and permission profiles.
Test progressive rollout and rollback.
Implement real exporters, metric fixtures, and recording and alert rules.
Maintain two consolidated dashboard pages, packaging, and runbooks.
Preserve all nine original domains and JSON definitions.
Keep planned signals visible until their owning implementation and tests pass.
Verify actual scrapes before reusing native collectors.

CMTC-802 retains the small two-cluster topology and evidence-before-teardown pattern from the pinned PoC. Adapt the root-copy bootstrap to protected root/cluster intermediates, pin agent/proxy/CRD inputs immutably, make required connectivity/security checks mandatory and convert evidence-printing checks into failing assertions. Establish the core encrypted path before adding the full observability stack.

Acceptance: API, DNS UDP/TCP, webhooks, kubelet, ingress, OAuth, operators, etcd, bootstrap/recovery and upgrades remain healthy. Failure stops rollout; rollback requires datapath and platform recovery, not label removal. Promtool rule checks/tests and Grafana imports cover success, denial, zero traffic, absent exporter and missing cluster series. Security-negative, resilience and performance suites pass the pinned version matrix before production support is stated.

## Tracking and completion

Canonical hierarchy: initiative → F01..F09 → EP01..EP09 → CMTC story → listed subtasks. [stories.csv](../agile/stories.csv) retains the existing 46 story IDs. PR 0 records the original static review. Current story states belong in the backlog and delivery status. Explicit architecture approval remains separate from implementation progress. Stories are closed by their acceptance evidence, not by a dashboard or desired label.
