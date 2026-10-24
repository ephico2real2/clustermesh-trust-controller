# CMTC background and decisions

This is the reconstructed project history and stakeholder motivation from the design conversation, not verbatim chat logs.

## Original problem
Cilium native workload mutual authentication and ztunnel were understood not to support ClusterMesh together in the researched release. The user wants native Cilium cross-cluster workload mTLS, **without Linkerd or Istio**, and an upstream-friendly implementation. Verify current version-specific limitations against pinned source before coding.

## Decisions made in conversation
1. Build **ClusterMesh Trust Controller** (CMTC) as Go Kubernetes operator for cross-cluster trust, policy and rotation, plus upstream Cilium ztunnel/ClusterMesh integration. Operator alone cannot enable unsupported datapath functionality.
2. Choose **Option A**: SPIRE X.509-SVID issuance, cert-manager upstream certificate authority, trust-manager public bundle distribution. One protected organizational root and cluster-specific intermediates. Never copy root private key to nodes/namespaces.
3. Use hub/spoke management and a lightweight **DaemonSet** for node-level namespace/pod inventory, configuration digest acknowledgment, health and latency; evaluate duplication with existing Cilium DaemonSet/Hive.

## Cross-cluster mTLS test-design decision — 2026-10-24

The user's principal-engineer blueprint is retained as a test-design reference, with its technical claims checked against the active fork before implementation. Keep CMTC responsible for trust lifecycle and intent, Cilium responsible for native remote endpoint discovery, policy and xDS, and node ztunnel responsible for workload TLS. A remote Workload record by itself does not prove trust or authorization. Mocks may diagnose serialization, stream lifecycle or telemetry in isolated tests; never feed them through a production side channel or treat them as end-to-end proof.

The end-to-end fixture must deploy the same application identity and a client in each cluster, distinguish backend responses by serving cluster, and assert local baseline plus cross-cluster communication in both directions. Test both Service and Pod-IP paths, including a non-80 application TCP port. Negative and recovery tests cover unenrolled/invalid SVIDs, unauthorized cluster binding, forbidden port, absent/stale/NACKed policy, trust mismatch, disconnect and restart. Correlate the actual image/source in both clusters, authenticated peer identities, effective policy verdicts, xDS state, request results and HBONE/TLS packet evidence. Keep WG/IPsec evidence separate. These are acceptance targets, not completed gates.

The source pin quoted by the blueprint (`beb276d2...`, Cilium v1.20.4) is historical for the active work; verify code against each recorded current source SHA. Do not assume SPIFFE URI equality or a common root identifies the originating cluster. Do not claim `Protected` from labels, certificate issuance, an xDS ACK, a screenshot or a mock result.

The active target is the user's enhanced `ephico2real2/cilium` fork; stock Cilium is not a substitute. However, the fork's current dirty xDS candidate still retains the ClusterMesh/ztunnel compatibility guard and only has local workload discovery. Its authorization stream accepts compiled resources and reports ACK metrics; it does not compile effective Cilium policy or gate admission on an acknowledged policy set. The paired ztunnel candidate can pass unresolved outbound connections through as raw TCP and treats an empty effective ALLOW set as allow. These observed gaps define implementation work; the existing Observe image is an older fork build and demonstrates reachability only. See the current source pins and next action in [CODEX_START_HERE.md](CODEX_START_HERE.md) and the detailed gates in [SECURITY_AND_FAILURE_TEST_MATRIX.md](../architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md#current-enhanced-fork-implementation-gates).
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
