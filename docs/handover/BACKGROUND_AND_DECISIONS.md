# CMTC background and decisions

<!-- CMTC_DOC_CONTEXT -->
Decision history: distinguish accepted requirements from later experimental implementation choices. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This page records project requirements and decision history.
It reconstructs the design conversation; it is not a verbatim transcript.
Later experiments do not replace the original design decisions automatically.

## Original problem

The researched release did not support the required ClusterMesh and ztunnel combination.
The user wants native Cilium cross-cluster workload mTLS without Linkerd or Istio.
The implementation must fit Cilium's architecture and support upstream review.
Verify version-specific limitations against pinned source before implementation.

## Requirements and original design decisions

1. Build CMTC as a Go Kubernetes operator for cross-cluster trust, policy, and rotation. Extend Cilium's native ztunnel integration. An operator cannot enable an unsupported datapath alone.
2. Use Option A: SPIRE X.509-SVID issuance, cert-manager as the upstream certificate authority, and trust-manager for public bundles. Keep one protected root and cluster-specific intermediates. Keep the root private key outside nodes and application namespaces.
3. Use hub/spoke management and a lightweight node DaemonSet for inventory, acknowledgments, health, and bounded probes. Reuse Cilium's enrollment and ZDS inventory. Avoid duplicate authority.
4. Let `NamespaceMTLSPolicy` manage `io.cilium/mtls-enabled: "true"`. `AllEligible` selects eligible application namespaces. `MatchSelectors` uses existing organizational metadata. AND applies within a selector; OR applies across selectors. Exclusions take precedence.
5. Preserve Kubernetes and OpenShift platform traffic. Protect system, control-plane, infrastructure, hosted-control-plane, and hostNetwork components from automatic enrollment. Define narrow interoperability rules; do not add a blanket bypass.
6. Keep node transport and workload mTLS as separate settings. Support none, WireGuard, or IPsec only where the pinned profile passes its tests. The primary target requires workload mTLS over WireGuard or IPsec. Reject unsupported combinations and silent downgrade.
7. Rotate trust in stages. Publish old and new public bundles before switching issuance. Verify real consumer acknowledgments and drain before retirement. Test emergency compromise separately.
8. Preserve all nine observability domains and original dashboard definitions. Present them through two consolidated Grafana pages: Operations and Workload Security. Keep planned signals visible until their metrics and acceptance tests exist. Instrument measured results; do not infer protection from labels.
9. Keep architecture, ADRs, source evidence, backlog, and security tests current as implementation proceeds. The original architecture-first planning phase is historical. It does not impose a new hold on authorized implementation.
10. Use the user's forks and qualified local increments. Build and test locally before publication. Current instructions defer CI, branch pushes, and image publication.

## Cross-cluster mTLS test-design decision — 2026-10-24

The user's blueprint remains a test-design reference.
Check its technical claims against the active fork before implementation.
CMTC owns trust lifecycle and intent.
Cilium owns native remote discovery, policy, and xDS delivery.
Node ztunnel owns workload TLS.
A remote Workload record does not prove trust or authorization.
Mocks can test isolated serialization, streams, and telemetry.
They cannot replace native production delivery or end-to-end evidence.

Deploy the same application identity and a client in each cluster.
Identify each response by its serving cluster.
Test local paths and both cross-cluster directions.
Test Service and Pod-IP paths on TCP/80, TCP/8080, and an arbitrary high port.
Negative tests cover unenrolled or invalid SVIDs, unauthorized cluster binding, and forbidden ports.
They also cover missing, stale, or NACKed policy, trust mismatch, disconnect, and restart.
Record exact images, peer identities, policy verdicts, xDS state, request results, and TLS packets.
Keep WireGuard and IPsec evidence separate.
These are acceptance targets, not completed gates.

The blueprint's `beb276d2...` source pin and Cilium v1.20.4 reference are historical.
Use the current source SHA for each increment.
SPIFFE URI equality or a shared root does not prove the originating cluster.
Labels, issuance, xDS ACKs, screenshots, and mocks cannot establish `Protected` alone.

The implementation target remains the user's enhanced `ephico2real2/cilium` fork.
The original audit found local-only workload discovery, missing effective policy, permissive fallback, and compatibility restrictions.
These are historical source findings and acceptance requirements.
Later source changes require their own tests and exact-image runtime qualification.
Use [delivery status](../agile/DELIVERY_STATUS.md) and the [security test matrix](../architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md) for their current disposition.

## Current source and runtime snapshot — 2026-10-25

| Item | State |
| --- | --- |
| Cilium source | `8bb97137fcc92b935171d60e59d7fb8a93714bd8` in the active fork checkout. |
| Cilium runtime | `4459d58ed3d98805f15c74298076025fc97dd540` in the retained two-cluster lab. Source changes after this SHA are not runtime proof. |
| Ztunnel source | `1609bfd38abdf4be671ad0d8144fecfa0b6d94b0`, plus an uncommitted terminal SPIRE stream-error correction. |
| Latest local ztunnel tests | The source and correction pass 568 full-suite tests and 2 diagnostic tests, formatting, and strict Clippy. |
| Activation | No runtime activation follows from those source tests. KVStoreMesh remains enabled; ztunnel remains disabled. |
| Delivery boundary | Local qualification continues. CI, pushes, and publication remain deferred. |

The original SPIRE design reuses Cilium's namespace/service-account registration path.
A separate CMTC registrar image was introduced later as an experiment inside the SPIRE server Pod.
That experiment does not establish an approved permanent registration owner.
[SPIRE registration design](../../SPIRE_REGISTRATION_DESIGN.md) records the difference and the required decision.
It also separates server Admin access, pending agent Admin permissions, credential delivery, and traffic protection.
A stream timeout does not prove target withdrawal or authorization denial.
Existing certificates and established flows require separate revocation tests.

## User stories behind the requirements

- Platform engineer: automatically enroll related namespaces based on existing organizational metadata and fix label drift.
- Security owner: grant explicit auditable namespace exclusions without silently permitting plaintext to protected destinations.
- PKI operator: common trust across clusters with no root key replication and safe CA rotation.
- SRE: see desired vs labeled vs actually protected pods; measure propagation and handshake latency and diagnose failures.
- Cluster administrator: preserve Kubernetes/OpenShift bootstrapping and upgrades regardless of mTLS and WireGuard/IPsec state.
- Upstream maintainer: keep changes native to Cilium's Go/Hive architecture, small, tested and reviewable.

## Scope boundaries

Defer workload-level exceptions until their design is explicit.
Limit the workload mTLS target to TCP until UDP and QUIC are designed.
Do not auto-enroll hostNetwork or platform namespaces.
Do not add a second traffic proxy.
Production claims require Cilium integration and passing negative tests.
