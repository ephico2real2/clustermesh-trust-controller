# Codex continuation / session handover

## Latest continuation — 2026-10-23

[CMTC PR #1](https://github.com/ephico2real2/clustermesh-trust-controller/pull/1) and [PR #2](https://github.com/ephico2real2/clustermesh-trust-controller/pull/2) are merged into main. [Merged-main CI 40028165414](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40028165414) passed at `793c47bb967660f5843c925e79b58f286bf431cc`. This remains Observe/baseline validation.

The user authorized implementation, deployment and CI with screenshots, plus copying demo apps. [CMTC PR #2](https://github.com/ephico2real2/clustermesh-trust-controller/pull/2), branch `feat/cmtc-observe-lab`, adds the Observe API/controller/node-inventory build, deployment/RBAC, Go tests, two-cluster CI and Playwright evidence. [CI run 40020608206](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40020608206) passed at `f81b955948d33ad187ed6891aca7c348ec27197e`; read [VALIDATION.md](../development/VALIDATION.md) for the precise evidence and [OBSERVE_LAB.md](../development/OBSERVE_LAB.md) for operation. The operator cannot mutate namespace labels or read CA Secrets; `EnforcementVerified` stays Unknown. Cilium workload mTLS/dual encryption and SPIRE/rotation remain pending.

The user subsequently confirmed ztunnel workload mTLS **plus** WireGuard/IPsec node transport as the primary end-to-end target. This supersedes the earlier optional-transport framing for that profile; none/mTLS-off remain explicit test controls. [EXISTING_LAB_REVIEW.md](../research/EXISTING_LAB_REVIEW.md) reviews their `cilium-implementation-poc` at commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`, including cert-manager/Hubble/ClusterMesh, public trust bundles, the WG exercise and isolated ztunnel demo. Reuse the test foundation while adapting its root-copy bootstrap; its observability workflow starts with WG disabled and does not establish layered encryption. Keep existing PoC/fork work intact.

Start with [SOURCE_AUDIT.md](../research/SOURCE_AUDIT.md), [sources.lock.json](../research/sources.lock.json) and [IMPLEMENTATION_PLAN.md](../architecture/IMPLEMENTATION_PLAN.md). Cilium v1.20.4 is pinned to `beb276d2f38d4aadfda14710acf8d14a0f1ba723`; the source audit itself is static. [Design PR #1](https://github.com/ephico2real2/clustermesh-trust-controller/pull/1) is the stacked implementation's base. All nine ADRs remain Proposed; user authorization permits the Observe implementation and fork development, without establishing runtime protection.

The [Istio/Linkerd comparison](../research/MESH_MTLS_COMPARISON.md) and [Cilium contract](../architecture/CILIUM_ZTUNNEL_CONTRACT.md) define remote identity, destination L4 authorization and fail-closed admission requirements. [Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1), branch `feat/cmtc-ztunnel-authorization-protocol`, adds only the version-pinned authorization protobuf, generated Go bindings and wire/reproducibility tests. It was ported from the audited release to upstream main `3b6e980b3d4eaa5be4532602ccb2bd54d8540dc4`, with Go 1.27.1 generators, and is merged into the fork at `a035a5892526afa2235b690c62c2f004b72aa9ab`. The fork also includes upstream `e5967e950b8f10ae514c58787e80d8e0192c15fd`. [Merged-main protocol CI](https://github.com/ephico2real2/cilium/actions/runs/40033037552) passed; full source checks are linked in VALIDATION.md. Existing Hubble branches are separate. Policy compilation/delivery, remote discovery, packet admission, identity issuance/verifier binding and transport composition remain open. The compatibility guard is retained. Review [observability findings](../../observability/docs/SOURCE_AUDIT.md) before instrumenting dashboards.

[Cilium dashboard PR #2](https://github.com/ephico2real2/cilium/pull/2) is merged into the fork at `33ab097444ac942f10606e236678bf55f6a9d498`, with [real-load CI](https://github.com/ephico2real2/cilium/actions/runs/40032696185) and immutable screenshots/query results linked in VALIDATION.md. Upstream #48563 already fixed remote workload propagation. The remaining Gateway All-filter fix preserves workload labels; this reproducer uses an external client for missing source labels because pod clients can retain their namespace/workload. The fork-only [CI PR #3](https://github.com/ephico2real2/cilium/pull/3) is merged at `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`, including upstream `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`. [Combined-source CI 40035107452](https://github.com/ephico2real2/cilium/actions/runs/40035107452) passed seven browser cases and 151,120 HTTP 200 responses across three separately validated load streams at head `221d435ecce12fdf19efb4ca71026ff1c889317b`. The reusable workflow accepts exact source/baseline SHAs, checks real traffic before PNGs and retains raw diagnostics. Merge only owned-repo PRs when checks permit. Do not enable automatic upstream merging. Upstream submission requires the operator's review and own wording under Cilium's AI policy.

## Decisions from the design sessions
- Build a native Cilium ClusterMesh + ztunnel cross-cluster mTLS solution; no Linkerd/Istio.
- Use **Go** for CMTC Hub, controllers, node DaemonSet, admission and Cilium control-plane extensions; Cilium Hive/cell conventions inside Cilium, controller-runtime/client-go for standalone operator; C/eBPF only for necessary datapath modifications.
- Option A: protected organizational root CA, cluster-specific intermediates, SPIRE-issued workload X.509-SVIDs, cert-manager UpstreamAuthority integration and trust-manager for **public** trust bundle distribution. Never copy root private signing keys to clusters/namespaces.
- Hub-and-spoke controller plus node-level DaemonSet for pod/node inventory, config acknowledgments, readiness and latency telemetry. Cilium remains enforcement owner; evaluate Hive module vs separate agent.
- `NamespaceMTLSPolicy` reconciles native namespace label `io.cilium/mtls-enabled: "true"`. Support `AllEligible` and `MatchSelectors` modes, OR across selectors, AND within selector; examples `company.net/lob=alpha` OR `company.net/mnemonic=delta`.
- Explicit namespace exclusions override inclusions; protected Kubernetes/OpenShift system/control-plane/infrastructure namespaces never auto-enroll. Avoid breaking API, DNS, webhooks, kubelet, etc. Namespace exclusion is not permission to bypass protected destination security.
- Target HBONE mTLS with WireGuard, IPsec or no L3 encryption; also preserve normal ClusterMesh operation when mTLS off. No silent plaintext fallback. Cilium currently has incompatibilities to solve.
- Nine Grafana dashboards; Prometheus recording/alerting rules; metrics for enrollment, pods, trust, handshake latency, transport, platform safety, DaemonSet and controller health.
- Agile structure: initiative -> features -> epics -> stories -> subtasks; ADRs, DoR, DoD, security gates and architecture diagrams.

## Current status
- Use the user's configured SSH Git access and human identity. Cilium signoff validation requires their real email from existing Cilium history; do not use a noreply signoff there.
- `NamespaceMTLSPolicy` is a deployed Observe-only API. Its Strict rejection is intentional and tested, not a missing CRD prerequisite. Other proposed CRDs remain design-only.
- Eleven browser pages are captured in CI. The live Observe page uses real telemetry; missing future domain signals are explicitly BLOCKED, not security test successes.
- The Cilium fork has a protocol foundation; it does not yet enforce cross-cluster workload mTLS. No namespace may be marked Protected from its label or an xDS ACK alone.

## Next implementation tasks
1. Review the protocol fork's exact source/image compatibility and CI; then implement real Authorization resource lifecycle and effective Cilium policy translation.
2. Add authenticated, cluster-qualified remote workload discovery with UID/recreation/removal semantics. Keep ZDS/netns enrollment local.
3. Resolve cluster identity issuance and peer-verifier binding; common-root trust plus a display-only cluster ID cannot isolate same-name service accounts.
4. Implement persistent fail-closed admission for missing policies, startup, reconnect, NACK and revocation. The selected proxy currently skips missing references.
5. Qualify same-node, inter-node and cross-cluster mTLS, then separate WireGuard and IPsec composition profiles before revising the compatibility guard or enabling Strict.
6. Preserve platform traffic, real security-negative tests and packet/identity evidence. Screenshots support those assertions; they cannot replace them.

## Important unresolved risks
- Default-on vs metadata-only inclusion must be explicitly selected, not ambiguously combined.
- Cluster intermediate CA compromise could sign identities for another cluster without issuance restrictions and verifier binding.
- Label reconciliation alone cannot fail close during namespace/pod creation races.
- Current Cilium ztunnel/ClusterMesh, L4 policy and WireGuard/IPsec composition limitations need source-level changes and testing.
- TLS handshake success alone does not prove WireGuard/IPsec encryption; separate node-layer evidence is needed.
- OpenShift's default CNI is typically OVN-Kubernetes; Cilium support profile must be verified.
- Control-plane interoperability must preserve native API TLS and DNS UDP without blanket security bypass.
