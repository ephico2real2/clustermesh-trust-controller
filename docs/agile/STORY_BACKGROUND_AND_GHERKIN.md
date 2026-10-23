# Story background and executable acceptance scenarios

## CMTC-501 / 505 — Metadata-driven namespace enrollment
**As a** platform engineer, **I want** CMTC to use existing LOB/mnemonic namespace labels, **so that** groups of application namespaces automatically enroll without per-namespace work.

Given `selectionMode=MatchSelectors` and a namespace with `company.net/lob=alpha`, when reconciled, then `io.cilium/mtls-enabled: "true"` is applied. Given `company.net/mnemonic=delta`, the same occurs. Given neither label, it is not selected. Given both conditions within one selector, AND semantics apply. In `AllEligible`, all eligible application namespaces enroll regardless of business labels. Namespace creation/recreation, relabeling and GitOps drift are tested.

## CMTC-502 / 506 — Exclusions
**As a** security owner, **I want** explicit exclusions to override selectors, **so that** exceptions are deterministic and auditable.

Given namespace `legacy-payments` matches inclusion and exclusion, when reconciled, then CMTC removes its managed enrollment label, emits a reason, and does not authorize traffic to protected namespaces. Unauthorized users cannot grant exclusions or alter reserved labels.

## CMTC-503 — Pod protection
**As an** SRE, **I want** actual per-pod protection readiness, **so that** labels cannot conceal a plaintext bypass.

Given an enrolled namespace with a new pod and missing SPIRE/ztunnel readiness, when the pod sends traffic, then protected traffic is denied by Cilium and the pod remains `PendingEnforcement`; when all prerequisites become ready, the pod is `Protected` after verified datapath state.

## CMTC-101..105 — Shared trust and rotation
**As a** PKI operator, **I want** a common trusted root with separate cluster intermediates, **so that** workloads authenticate across clusters without copying root signing keys.

Given old Root A, when Root B is introduced, then all clusters acknowledge actual trust consumption before issuance switches; all SVIDs rotate and probes pass before Root A retires. Partitioned clusters block unsafe retirement; emergency compromise uses a separate response procedure.

## CMTC-301..305 / 401..404 — Native encryption and authorization
**As a** Cilium maintainer, **I want** remote SPIFFE identity, HBONE and L4 policy to work across ClusterMesh, **so that** workloads remain authenticated and authorized with optional WireGuard/IPsec.

Given transport none/WireGuard/IPsec, when protected TCP connects, then remote identity and policy are verified and the expected transport is independently observed. Unknown identity, unauthorized L4 flows and lost required encryption fail closed. Mixed unsupported modes are rejected.

## CMTC-601..606 — Platform safety
**As a** Kubernetes/OpenShift administrator, **I want** system namespaces guarded, **so that** enabling mTLS does not break cluster operations.

Given platform-protected namespaces, when selectors match, then they remain unenrolled. During canary rollout, API/DNS/webhook/kubelet/ingress/operator probes pass; failures stop progression and rollback is marked successful only after datapath recovery is verified.

## CMTC-701.. — Observability
**As an** SRE, **I want** coverage, latency, CA, authentication, transport and control-plane dashboards, **so that** I can distinguish missing data from healthy zero-error behavior.

Given instrumented CMTC/Cilium metrics, when a failure occurs, then Prometheus alerts and Grafana reflect it with bounded labels and drilldown logs. PromQL is validated against actual metric samples; no sample dashboard data is represented as production telemetry.

## Universal Definition of Done
Code/design review, unit and integration tests, negative security tests, metrics and dashboards validated, source version pinned, ADR updated, recovery documented, platform health preserved, CI green, no unauthorized plaintext fallback. Stories needing Cilium changes cannot be closed by operator-only behavior.
