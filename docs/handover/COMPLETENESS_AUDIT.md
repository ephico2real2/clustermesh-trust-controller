# Completeness audit — 2026-10-23

Implementation continuation: [OBSERVE_LAB.md](../development/OBSERVE_LAB.md) supersedes the historical design-only inventory below for the experimental observation API/controller/agent/CI slice. No encrypted-path capability follows from that implementation; use actual CI evidence for deployment claims.

## Continuation source review

The [source audit](../research/SOURCE_AUDIT.md) now records an immutable Cilium v1.20.4 baseline, exact interfaces and unresolved gaps. All nine ADRs have specific evidence/acceptance gates; an initial threat model and incremental PR plan exist. The [observability audit](../../observability/docs/SOURCE_AUDIT.md) covers all nine dashboards and rule/monitor scaffolding. This completes initial static review, not runtime compatibility or architecture approval. The input manifest's 38 hashes all matched (39 files including the manifest); the current manifest is refreshed for the expanded design snapshot.

## Captured from conversation
- Native ztunnel + ClusterMesh, no Linkerd/Istio; Go/Hive and controller-runtime.
- CMTC Hub + node DaemonSet; cluster and namespace/pod tracking; configuration and latency.
- Common protected root, per-cluster intermediate, SPIRE, cert-manager, trust-manager, cross-cluster CA sync and staged rotation.
- NamespaceMTLSPolicy CRD, automatic Cilium enrollment label, default eligible scope, metadata inclusion via LOB/mnemonic, OR selector logic, explicit exclusion precedence and drift repair.
- Kubernetes/OpenShift system/control-plane protection, critical platform communications, hostNetwork/hosted control planes, rollout gates.
- Workload mTLS on/off, transport none/WireGuard/IPsec, fail closed, policy, UDP/TCP and MTU concerns.
- Prometheus metrics, nine Grafana dashboards, alerts, SLOs, Hubble/logs, OpenShift UWM.
- Agile features/epics/stories/subtasks, DoR/DoD, architecture/sequence diagrams, threat model, source verification queue, Codex prompt.

## Not yet implemented / must not misrepresent
- Cilium cross-cluster ztunnel integration, remote identity binding, fail-closed datapath, dual-layer encryption.
- OpenAPI CRD schemas and validation, Go controllers/DaemonSet, admission webhook, Helm charts, CI, end-to-end tests.
- Grafana imports and Prometheus metric instrumentation; existing JSON/YAML are untested starters.
- Verified source-level compatibility and OpenShift supported Cilium topology.

## Prior package issues fixed in this revision
- ADRs were short placeholders: expanded with decision direction, alternatives and evidence gates.
- Generic backlog acceptance language: supplemented with concrete scenario-based stories.
- Background rationale and handover prompt were incomplete: added narrative, security test matrix and master Codex prompt.

## Remaining uncertainty
No archive can replace source-level testing. Claims about Cilium APIs and compatibility must be verified on pinned versions before implementation. Original conversation is represented by a reconstructed decision history, not a verbatim export.
