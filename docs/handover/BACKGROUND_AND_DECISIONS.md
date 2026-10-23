# CMTC background and decisions

This is the reconstructed project history and stakeholder motivation from the design conversation, not verbatim chat logs.

## Original problem
Cilium native workload mutual authentication and ztunnel were understood not to support ClusterMesh together in the researched release. The user wants native Cilium cross-cluster workload mTLS, **without Linkerd or Istio**, and an upstream-friendly implementation. Verify current version-specific limitations against pinned source before coding.

## Decisions made in conversation
1. Build **ClusterMesh Trust Controller** (CMTC) as Go Kubernetes operator for cross-cluster trust, policy and rotation, plus upstream Cilium ztunnel/ClusterMesh integration. Operator alone cannot enable unsupported datapath functionality.
2. Choose **Option A**: SPIRE X.509-SVID issuance, cert-manager upstream certificate authority, trust-manager public bundle distribution. One protected organizational root and cluster-specific intermediates. Never copy root private key to nodes/namespaces.
3. Use hub/spoke management and a lightweight **DaemonSet** for node-level namespace/pod inventory, configuration digest acknowledgment, health and latency; evaluate duplication with existing Cilium DaemonSet/Hive.
4. **NamespaceMTLSPolicy** automatically manages `io.cilium/mtls-enabled: "true"`. All eligible application namespaces default-on via `AllEligible`; `MatchSelectors` supports existing `company.net/lob=alpha` OR `company.net/mnemonic=delta` metadata. AND within a selector; OR across selectors. Exclusions override inclusions.
5. Protect Kubernetes/OpenShift system/control-plane/infrastructure namespaces from auto-enrollment. Preserve API, etcd, kubelet, DNS (UDP/TCP), webhook, ingress, OAuth, CNI, operators, hosted control-plane and hostNetwork traffic. No blanket bypass.
6. Network modes: no transport encryption, WireGuard or IPsec; mTLS enabled or disabled. Need proof of double encryption composition, policy preservation, MTU/MSS, fail-closed behavior and remote identity resolution. Mixed unsupported modes rejected.
7. CA rotation: staged old+new trust bundle, real SPIRE/ztunnel acknowledgment, issuance switch, drain, old-root retirement. Emergency revocation separate.
8. Observability: nine Grafana dashboards; Prometheus/Alertmanager, OpenShift User Workload Monitoring, Hubble/logs, namespace/pod coverage, latency, CA, transport, security, platform and operator metrics. Metrics must be instrumented, not inferred from labels.
9. Architecture first: high-level/inner coordination diagrams, sequence flows, ADRs, feature/epic/story/subtask backlog, DoR/DoD, test matrix and security reviews before coding.
10. Repository `ephico2real2/clustermesh-trust-controller` exists; prior GitHub write attempts returned 403. No files were committed via that connection. Codex handover via ZIP was chosen.

## User stories behind the requirements
- Platform engineer: automatically enroll related namespaces based on existing organizational metadata and fix label drift.
- Security owner: grant explicit auditable namespace exclusions without silently permitting plaintext to protected destinations.
- PKI operator: common trust across clusters with no root key replication and safe CA rotation.
- SRE: see desired vs labeled vs actually protected pods; measure propagation and handshake latency and diagnose failures.
- Cluster administrator: preserve Kubernetes/OpenShift bootstrapping and upgrades regardless of mTLS and WireGuard/IPsec state.
- Upstream maintainer: keep changes native to Cilium's Go/Hive architecture, small, tested and reviewable.

## Scope boundaries
Initial workload-level exceptions deferred; TCP mTLS only until UDP/QUIC explicitly designed; hostNetwork and platform namespaces not auto-enrolled; no separate proxy; no production claim until Cilium integration and negative tests pass.
