# Codex continuation / session handover

## Latest continuation — 2026-10-23

The user subsequently confirmed ztunnel workload mTLS **plus** WireGuard/IPsec node transport as the primary end-to-end target. This supersedes the earlier optional-transport framing for that profile; none/mTLS-off remain explicit test controls. [EXISTING_LAB_REVIEW.md](../research/EXISTING_LAB_REVIEW.md) reviews their `cilium-implementation-poc` at commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b`, including cert-manager/Hubble/ClusterMesh, public trust bundles, the WG exercise and isolated ztunnel demo. Reuse the test foundation while adapting its root-copy bootstrap; its observability workflow starts with WG disabled and does not establish layered encryption. Keep existing PoC/fork work intact.

Start with [SOURCE_AUDIT.md](../research/SOURCE_AUDIT.md), [sources.lock.json](../research/sources.lock.json) and [IMPLEMENTATION_PLAN.md](../architecture/IMPLEMENTATION_PLAN.md). Cilium v1.20.4 is pinned to `beb276d2f38d4aadfda14710acf8d14a0f1ba723`; the audit is static only. The local archive was initialized as Git with a README base and `design/cilium-source-audit` branch, using the configured ephico2real2 identity and SSH remote. Check Git/PR state for publication. No Go module, CRD generation, CI or enforcement was added. All nine ADRs remain Proposed.

Continue PR 1 interface/security review before live enrollment or implementation scaffolding. Reuse existing Cilium SPIRE enrollment, but verify the external credential path and cluster binding. The chart's encryption types are exclusive; application L4 authorization, remote discovery, packet gating, platform interoperability and transport composition remain unresolved. Review [observability findings](../../observability/docs/SOURCE_AUDIT.md) before instrumenting dashboards.

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
- Historical handover: earlier GitHub connector writes returned 403 `Resource not accessible by integration`; no GitHub commit had succeeded at archive creation. The latest continuation above supersedes that state; use the user's configured SSH Git access and identity.
- Existing observability JSON/YAML is **starter scaffolding**, not live tested. All `security.cmtc.io/v1alpha1` CRDs are design-only.
- Cilium ztunnel + ClusterMesh remains a research/upstream integration task; no functional Go operator or Cilium patch has been produced.

## First Codex tasks
1. Import this directory into `ephico2real2/clustermesh-trust-controller` on a design branch and open a design PR.
2. Pin actual Cilium version/commit and audit ClusterMesh, ztunnel, HBONE, ZDS/xDS, endpoint identity, encryption config, eBPF hooks, network policy and hostNetwork/UDP behavior. Verify all assumptions against source.
3. Complete ADRs and threat model before writing enforcement code.
4. Generate CRD OpenAPI schemas and test policy semantics (including excluded-to-enrolled, admission races and platform namespaces).
5. Scaffold Go module, controller-runtime, tests, metrics; do not claim `Protected` until Cilium datapath verification exists.
6. Validate dashboards/rules against real metric contracts and a test Prometheus.

## Important unresolved risks
- Default-on vs metadata-only inclusion must be explicitly selected, not ambiguously combined.
- Cluster intermediate CA compromise could sign identities for another cluster without issuance restrictions and verifier binding.
- Label reconciliation alone cannot fail close during namespace/pod creation races.
- Current Cilium ztunnel/ClusterMesh, L4 policy and WireGuard/IPsec composition limitations need source-level changes and testing.
- TLS handshake success alone does not prove WireGuard/IPsec encryption; separate node-layer evidence is needed.
- OpenShift's default CNI is typically OVN-Kubernetes; Cilium support profile must be verified.
- Control-plane interoperability must preserve native API TLS and DNS UDP without blanket security bypass.
