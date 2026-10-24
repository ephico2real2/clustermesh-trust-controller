# Agile delivery backlog

**9 features, 9 delivery epics, 46 delivery stories, plus investigative epic spike EP10.** See `stories.csv` for importable rows, subtasks, acceptance and DoD.

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

- **CMTC-101 — SPIRE cert-manager UpstreamAuthority spike** (P0/P1 per CSV). Subtasks: Validate certificate chain, issuer and SVID issuance. Acceptance: automated success, failure and security scenarios with documented metrics. Status: In progress. Local SPIRE credential work separates the agent ADS TLS identity from workload signing keys, wires delegated proxy attestation, and prepares cluster-local issuer/ADS keys with public CSRs only. The isolated two-node fixture verifies issuer/ADS and client/server SVID chains, with 10/10 cross-node mTLS requests, TLS record/canary evidence and native mutual_tls telemetry. Its unenrolled-source plaintext-bypass negative case failed; see [SPIRE_SPIKE.md](../development/SPIRE_SPIKE.md). Rotation, issuer-fault and cross-cluster acceptance remain open. [Issue #7](https://github.com/ephico2real2/clustermesh-trust-controller/issues/7) tracks bounded retries, authenticated acknowledgments, Cilium slog/Hive health, registration and proxy startup gates. Local Podman race tests cover the initial operator retry/RPC acknowledgment slice; this is not mTLS acceptance.
- **CMTC-102 — Public trust bundle distribution** (P0/P1 per CSV). Subtasks: trust-manager Bundle reconciliation and namespace scoping. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-103 — Cluster trust sync protocol** (P0/P1 per CSV). Subtasks: Versioned digests; acknowledgment and trust reload verification. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-104 — CA rotation state machine** (P0/P1 per CSV). Subtasks: Dual-root overlap; issuance switch; drain; emergency revocation. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-105 — Cluster identity issuance boundaries** (P0). `mesh.example.com` is an example SPIFFE trust domain: an identity realm, independent of application DNS names and ports. Trust requires verified certificates and trusted CA bundles. With the same domain, namespace and service account, two clusters have the same SPIFFE ID unless another verified cluster binding distinguishes them. Subtasks: constrain issuance to attested workloads; choose cluster-specific trust domains with explicit peer trust or another cryptographically verified cluster binding; enforce issuer boundaries. Acceptance: legitimate cross-cluster identities succeed, while same-name foreign-cluster impersonation, unauthorized issuers and untrusted domains fail. A common root or matching domain string alone cannot pass. See [background and acceptance scenarios](STORY_BACKGROUND_AND_GHERKIN.md#cmtc-105--cluster-identity-issuance-boundaries). Status: Planned; identity design and runtime acceptance remain open.

### F05 — Cilium Native Cross-Cluster mTLS
**EP05: Remote identities, HBONE, policy**

- **CMTC-401 — Remote workload discovery to ztunnel** (P0/P1 per CSV). Subtasks: Trace ClusterMesh identities; remote xDS/ZDS mapping. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-402 — Cross-cluster HBONE connection PoC** (P0/P1 per CSV). Subtasks: Authenticated TCP across two clusters; identity checks. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-403 — Policy enforcement and fail-closed** (P0/P1 per CSV). Subtasks: Pin proxy authorization protocol; preserve L4 authorization; block bypass and unknown identities. Acceptance: automated success, failure and security scenarios with documented metrics. Status: In progress; [Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1) supplies protocol bindings/wire tests only. [Cilium PR #6](https://github.com/ephico2real2/cilium/pull/6) adds the real Go Authorization delta transport and typed desired-state cache, tested on Linux ARM64/AMD64 (150 race-enabled tests/subtests each). Effective Cilium policy production/workload references, authenticated remote discovery and persistent admission remain open. The SPIRE fixture reproduced the admission gap: an unenrolled source received HTTP 200 from an enrolled destination over plaintext; [issue #8](https://github.com/ephico2real2/clustermesh-trust-controller/issues/8) remains open. The [local CNP/CCNP experiment](../research/PLAINTEXT_ENFORCEMENT.md) blocked direct port-80 plaintext while preserving mTLS, including tested host paths; additive allows reopened default-deny without an explicit deny. The native authenticated-only rule at local Cilium `f052d127` now passes 57 multiport/post-restart checks without CNP/CCNP/KNP, 1,398 continuous restart probes, 6,000 authenticated HTTP responses and 900 rejected unenrolled attempts; [immutable evidence](https://github.com/ephico2real2/clustermesh-trust-controller/blob/1c192a5ee84fb5218cb1385fdd9c5bf45ca69e1a/2026-10-24T0509Z-local-authenticated-only-f052d127/README.md). General destination permissions, missing-policy/first-packet admission, platform exceptions and ClusterMesh remain open.
- **CMTC-404 — Service translation and endpoint race tests** (P0/P1 per CSV). Subtasks: ClusterIP/global services; node failover; identity cache races. Acceptance: automated success, failure and security scenarios with documented metrics.

### EP10 — Investigative spike under F05: per-node Envoy with CMTC and ztunnel

[GitHub epic spike #9](https://github.com/ephico2real2/clustermesh-trust-controller/issues/9)
tracks the user's alternative per-node Envoy proposal. Investigate dynamic SDS/xDS,
TLS termination/passthrough, verified workload identity preservation, mandatory
capture, fail-closed lifecycle, health probes, Cilium policy and transport cost.
Acceptance requires source-backed comparison and a tested recommendation/ADR;
port lists and a shared proxy identity cannot replace workload authentication.
This does not select Envoy or interrupt CMTC-403's native destination rule work.

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
- **CMTC-704 — Grafana dashboards** (P0/P1 per CSV). Subtasks: Preserve all nine original JSON definitions and consolidate their full domain/metric coverage into two meaningful dashboards; validate types, cluster scoping, unavailable signals and both-theme rendering. Acceptance: automated success, failure and security scenarios with documented metrics. The Workload Security page incorporates the 12 experimental native-mTLS panels without changing their query semantics, both-theme real-load captures, an actual metric inventory and exclusive TCP outcome percentages following the user's diagram-kit skill. Future protection/handshake signals remain unavailable; see [SPIRE qualification](../development/SPIRE_SPIKE.md).
- **CMTC-705 — Prometheus recording/alert rules** (P0/P1 per CSV). Subtasks: Rules, PromQL validation, SLO alerts. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-706 — OpenShift UWM and Kubernetes monitoring** (P0/P1 per CSV). Subtasks: ServiceMonitor/PodMonitor/PrometheusRule, RBAC and TLS. Acceptance: automated success, failure and security scenarios with documented metrics.

### F09 — Delivery, Security & Quality
**EP09: CI/CD, docs, E2E and release**

- **CMTC-801 — Go project scaffold and CI** (P0/P1 per CSV). Subtasks: Lint, unit/envtest, dependency security checks. Acceptance: automated success, failure and security scenarios with documented metrics.
- **CMTC-802 — Two-cluster KIND integration suite** (P0/P1 per CSV). Subtasks: Positive/negative mTLS and CA rotation. Acceptance: automated success, failure and security scenarios with documented metrics. Supporting harness follow-up: Hubble run 40055777499 stopped on an initial Gateway HTTP 503 immediately after Programmed/rollout; no load was started. The local image-matched Hubble run passed 151,200/151,200 requests. Reproduce and fix the service-readiness race locally before rerunning that CI qualification. This is separate from the current CMTC-101 trust/mTLS priority.
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
