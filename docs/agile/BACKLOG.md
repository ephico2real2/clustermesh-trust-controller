# Agile delivery backlog

**9 features, 9 epics, 46 stories.** See `stories.csv` for importable rows, subtasks, acceptance and DoD.

The [pinned source audit](../research/SOURCE_AUDIT.md) supplies initial static evidence for CMTC-001/002; neither is runtime complete and CMTC-003 is unapproved. Follow the [incremental PR plan](../architecture/IMPLEMENTATION_PLAN.md) for dependencies and explicit acceptance gates. This file and `stories.csv` define canonical IDs; the older architecture and observability package numbering is superseded.

## Definition of Ready
- Requirement, dependency and security boundary identified.
- Relevant Cilium behavior verified against pinned source or flagged as a spike.
- Acceptance tests and metrics source identified.
- Owner, estimates and rollout plan agreed.

## Definition of Done
- Reviewed Go/Cilium design or code; tests and security-negative cases pass.
- No unauthorized plaintext fallback; protected status backed by actual enforcement evidence.
- No Kubernetes/OpenShift control-plane connectivity regression.
- Metrics, alerting, documentation, ADR and recovery procedure updated.
- Cross-cluster certificate lifecycle and compatibility evidence recorded where applicable.

## Planned feature / epic / stories

### F01 — Architecture & Upstream Research
**EP01: Source compatibility and threat model**

- **CMTC-001 — Pin Cilium version and map ztunnel/ClusterMesh APIs** (P0). Subtasks: immutable pin; trace local/remote discovery, issuance, interception and policy; distinguish source evidence from runtime proof. Acceptance: every interface has a pinned citation or named gap and test; deep datapath/transport traces remain open. Status: In review, static baseline only.
- **CMTC-002 — Threat model cross-cluster identity and CA compromise** (P0). Subtasks: assets/boundaries; identity spoofing; signing-key exposure; downgrade; stale ACK; platform failure. Acceptance: cluster impersonation, first-packet, authorization and rotation threats each map to owner, mitigation and negative test; residual risks explicitly reviewed. Status: Draft.
- **CMTC-003 — Approve architecture ADRs and security gates** (P0). Subtasks: ownership/protocol review; disposition all nine ADRs; identity, observation, packet-gate and platform contracts. Acceptance: explicit architecture/security approval; source review alone cannot set Accepted. Status: Planned, awaiting review.

### F02 — Namespace Policy & Enrollment
**EP02: CRD, selectors, labels, admission**

- **CMTC-501 — Automatic namespace enrollment** (P0/P1 per CSV). Subtasks: Watch namespaces; apply fixed Cilium label; drift repair. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-502 — Explicit namespace exclusion** (P0/P1 per CSV). Subtasks: Names and selector exclusion; label removal; audit. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-503 — Pod enforcement readiness** (P0/P1 per CSV). Subtasks: Watch pods; verify Cilium StateDB/ztunnel state; fail-closed gate. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-504 — Namespace/pod enrollment metrics** (P0/P1 per CSV). Subtasks: Coverage gauges; duration histograms; dashboards. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-505 — Metadata-driven LOB/mnemonic inclusion** (P0/P1 per CSV). Subtasks: Kubernetes LabelSelector matching; OR across selectors. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-506 — Exclusion precedence** (P0/P1 per CSV). Subtasks: Platform and exclusion precedence; conflict tests. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-507 — Dynamic namespace metadata changes** (P0/P1 per CSV). Subtasks: Watch relabel; UID deletion/recreation; GitOps field ownership. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-508 — Selector explanation and audit** (P0/P1 per CSV). Subtasks: Conditions, events, bounded metrics and policy reasons. Acceptance: automated success, failure and security scenarios with documented metrics.

### F03 — Node Agent & Control Plane
**EP03: Hub, cluster controller, DaemonSet**

- **CMTC-201 — Hub cluster registry and status** (P0/P1 per CSV). Subtasks: Registration; auth; cluster conditions; reconcilers. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-202 — Node-agent DaemonSet prototype** (P0/P1 per CSV). Subtasks: Per-node pod inventory; config digest; local readiness. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-203 — Versioned configuration acknowledgments** (P0/P1 per CSV). Subtasks: ObservedGeneration; digest; drift and lag metrics. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-204 — HA and partition tolerance** (P0/P1 per CSV). Subtasks: Leader election; cached trust; cluster disconnection tests. Acceptance: automated success, failure and security scenarios with documented metrics.

### F04 — Trust, SPIRE & Rotation
**EP04: Root/intermediate and trust synchronization**

- **CMTC-101 — SPIRE cert-manager UpstreamAuthority spike** (P0/P1 per CSV). Subtasks: Validate certificate chain, issuer and SVID issuance. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-102 — Public trust bundle distribution** (P0/P1 per CSV). Subtasks: trust-manager Bundle reconciliation and namespace scoping. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-103 — Cluster trust sync protocol** (P0/P1 per CSV). Subtasks: Versioned digests; acknowledgment and trust reload verification. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-104 — CA rotation state machine** (P0/P1 per CSV). Subtasks: Dual-root overlap; issuance switch; drain; emergency revocation. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-105 — Cluster identity issuance boundaries** (P0/P1 per CSV). Subtasks: Constrain URI namespace; bind identity to cluster and workload. Acceptance: automated success, failure and security scenarios with documented metrics.

### F05 — Cilium Native Cross-Cluster mTLS
**EP05: Remote identities, HBONE, policy**

- **CMTC-401 — Remote workload discovery to ztunnel** (P0/P1 per CSV). Subtasks: Trace ClusterMesh identities; remote xDS/ZDS mapping. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-402 — Cross-cluster HBONE connection PoC** (P0/P1 per CSV). Subtasks: Authenticated TCP across two clusters; identity checks. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-403 — Policy enforcement and fail-closed** (P0/P1 per CSV). Subtasks: Preserve L4 authorization; block bypass and unknown identities. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-404 — Service translation and endpoint race tests** (P0/P1 per CSV). Subtasks: ClusterIP/global services; node failover; identity cache races. Acceptance: automated success, failure and security scenarios with documented metrics.

### F06 — Network Encryption Compatibility
**EP06: WireGuard/IPsec/none**

- **CMTC-301 — Investigate encryption datapath** (P0/P1 per CSV). Subtasks: Trace hooks, encapsulation, MTU/MSS and strict encryption. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-302 — Discover transport configuration** (P0/P1 per CSV). Subtasks: Observe Cilium modes and cluster capability matrix. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-303 — Prevent downgrade and plaintext fallback** (P0/P1 per CSV). Subtasks: Datapath negative tests, missing keys and failure modes. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-304 — WireGuard + HBONE interoperability** (P0/P1 per CSV). Subtasks: Dual-layer packet captures, performance, routing. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-305 — IPsec + HBONE interoperability** (P0/P1 per CSV). Subtasks: XFRM, key rotation, MTU, performance and failures. Acceptance: automated success, failure and security scenarios with documented metrics.

### F07 — Kubernetes & OpenShift Safety
**EP07: Platform classification and connectivity**

- **CMTC-601 — Discover platform and control-plane inventory** (P0/P1 per CSV). Subtasks: kubeadm/OpenShift/hosted control planes; hostNetwork. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-602 — Protect system namespaces from enrollment** (P0/P1 per CSV). Subtasks: Classification precedence; admission and policy validation. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-603 — Validate critical platform traffic** (P0/P1 per CSV). Subtasks: API, DNS UDP/TCP, kubelet, webhooks, ingress, operators. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-604 — Progressive rollout and rollback** (P0/P1 per CSV). Subtasks: Canary, health gates, abort, verified recovery. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-605 — Platform health telemetry** (P0/P1 per CSV). Subtasks: Probe success, latency, blocked policy changes. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-606 — OpenShift supported profile** (P0/P1 per CSV). Subtasks: SCC, CNI support, operator upgrades, ClusterOperator conditions. Acceptance: automated success, failure and security scenarios with documented metrics.

### F08 — Observability & Grafana
**EP08: Metrics, dashboards, alerting**

- **CMTC-701 — Metric schema and ownership** (P0/P1 per CSV). Subtasks: Types, bounded labels, existing vs new sources. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-702 — Instrument Go exporters** (P0/P1 per CSV). Subtasks: Controller/agent metrics, endpoints, tests. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-703 — Instrument Cilium/ztunnel authentication** (P0/P1 per CSV). Subtasks: Handshakes, identity failures, policy denials, latency. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-704 — Grafana dashboards** (P0/P1 per CSV). Subtasks: Import and validate nine JSON dashboards. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-705 — Prometheus recording/alert rules** (P0/P1 per CSV). Subtasks: Rules, PromQL validation, SLO alerts. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-706 — OpenShift UWM and Kubernetes monitoring** (P0/P1 per CSV). Subtasks: ServiceMonitor/PodMonitor/PrometheusRule, RBAC and TLS. Acceptance: automated success, failure and security scenarios with documented metrics.

### F09 — Delivery, Security & Quality
**EP09: CI/CD, docs, E2E and release**

- **CMTC-801 — Go project scaffold and CI** (P0/P1 per CSV). Subtasks: Lint, unit/envtest, dependency security checks. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-802 — Two-cluster KIND integration suite** (P0/P1 per CSV). Subtasks: Positive/negative mTLS and CA rotation. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-803 — Resilience and performance testing** (P0/P1 per CSV). Subtasks: Chaos, partitions, latency, CPU, throughput, MTU. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-804 — Helm/GitOps packaging and runbooks** (P0/P1 per CSV). Subtasks: Charts, RBAC, SCC, upgrade and rollback docs. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-805 — Upstream design proposal and PR plan** (P0/P1 per CSV). Subtasks: Cilium CFP/issue, maintainers, focused patches. Acceptance: automated success, failure and security scenarios with documented metrics.

## Proposed milestone gates
1. Sprint 0: pinned source review, completed interface traces, ADR disposition, threat model and acceptance matrix.
2. Sprint 1, after architecture confirmation: Go/CI/schema scaffold, pure policy evaluation, selectors, exclusions and dry-run classification. Live labels require the packet/platform gates.
3. Sprint 2: versioned observation contract, lightweight node agent and telemetry; enforcement remains unverified until Cilium integration passes. No label-only Protected status.
4. Sprint 3: SPIRE/cert-manager/trust-manager trust sync and staged rotation.
5. Sprint 4-5: ClusterMesh remote identity and HBONE mTLS with policy/fail-closed tests.
6. Sprint 6: WireGuard/IPsec/no-transport encryption matrix and MTU/performance.
7. Sprint 7: Kubernetes/OpenShift safety and progressive rollout.
8. Sprint 8: dashboards, alerts, resilience, packaging and upstream review.

**Sprint durations and delivery estimates are not commitments; major upstream research risks remain.**
