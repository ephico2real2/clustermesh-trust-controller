# Security, encryption and failure test matrix

**Acceptance targets; none executed in the initial source audit.** Use the [pinned baseline and gaps](../research/SOURCE_AUDIT.md), [threat model](THREAT_MODEL.md) and [implementation gates](IMPLEMENTATION_PLAN.md). A test result must record exact versions, topology, identity/policy expectations and independent packet/transport evidence before a row can pass.

The primary profile requires workload mTLS plus WG or IPsec transport on the same cross-cluster flow. The [existing lab review](../research/EXISTING_LAB_REVIEW.md) identifies topology/evidence patterns and historical failures to reproduce. A demo report that exits zero while printing trouble is not a passing assertion; required negative checks and the multi-cluster suite must fail the qualification job on failure.

| Scenario | Expected behavior | Evidence |
|---|---|---|
| App A -> App B across clusters with no WireGuard/IPsec | Valid SPIFFE identities and HBONE TLS; policy enforced | TLS peer identity, traffic trace, denial tests |
| Same path over WireGuard | mTLS plus node encryption, no plaintext fallback | ztunnel metrics, WG peer state and packet capture |
| Same path over IPsec | mTLS plus XFRM transport protection | TLS metrics, XFRM state, packet capture |
| mTLS disabled, WireGuard/IPsec on/off | Existing supported ClusterMesh behavior unchanged | Baseline connectivity suite |
| Unknown remote identity | Reject protected connection | Auth failure, denied flow |
| Forged foreign-cluster SPIFFE URI | Reject unauthorized identity despite common root | Negative SVID test |
| Excluded namespace -> protected namespace | Deny unless explicit compatible authorization | Packet capture and policy verdict |
| Newly created/relabelled pod before ztunnel ready | No unprotected connection | Race stress test |
| Missing SVID or SPIRE down | No new unauthenticated protected connections | Chaos test |
| Hub partition / trust bundle drift | Cached verified trust where safe; no unsafe CA retirement | Digest, readiness, partition test |
| Root rotation old+new overlap | New SVIDs work everywhere before old root removed | End-to-end handshake matrix |
| WireGuard key missing / IPsec XFRM stale | No silent transport downgrade when required | Kernel/flow inspection |
| DNS UDP/TCP, API, webhook, kubelet | Control-plane communication remains functional | Probes, cluster health |
| OpenShift operator upgrades / hosted control plane | No unsafe enrollment or degradation | ClusterOperator conditions, operator tests |
| Node reboot / Cilium upgrade / ztunnel crash | Safe reconvergence and fail-closed posture | Restart tests |
| MTU and service translation | No hidden fragmentation/routing regressions | p95/p99 latency, MTU captures |

**Release gate:** An end-to-end encrypted connection is not proof of correct authorization. A namespace label is not proof of enforcement. No production support claims without negative security tests.

## Two-cluster application and ztunnel test design

The user's October 24 architecture blueprint is a test-design input, not source-of-truth for the active implementation. Its ownership split is retained: CMTC coordinates enrollment and trust lifecycle; the user's enhanced `ephico2real2/cilium` fork owns endpoint discovery, interception, policy and xDS; ztunnel authenticates and protects workload connections. Recheck every interface against the active fork and ztunnel source pins, and build/deploy the exact fork image used for each test. The blueprint's Cilium v1.20.4 / `beb276d2f38d4aadfda14710acf8d14a0f1ba723` pin does not describe the current fork work.

### Topology and positive path

Install the same application identity (namespace, service account, labels and image) in both mesh clusters, with a local client in each cluster. Give the two backend instances distinguishable responses so evidence identifies which cluster served each request. Assert, separately:

| Caller | Destination | Expected result |
|---|---|---|
| Cluster A client | A backend | Local baseline succeeds. |
| Cluster A client | B backend | Cross-cluster authenticated request succeeds. |
| Cluster B client | B backend | Local baseline succeeds. |
| Cluster B client | A backend | Reverse cross-cluster authenticated request succeeds. |

Keep service VIP and direct Pod-IP tests distinct. Exercise TCP/80, TCP/8080 and an arbitrary high port such as TCP/31337; the high port is a port-independence probe, not a prescribed allowlist. Policy must attach to workload identity and the original application tuple, not a guessed port list or HBONE port. During load, retain per-direction request totals and responses, verified client/server SPIFFE IDs, the ztunnel TLS/HBONE decision, xDS resource state, and packet captures from the same run.

### Negative and recovery path

For both directions, try a non-enrolled or invalid-SVID client, an unauthorized cluster identity, an allowed identity on a denied application port, missing or stale policy, xDS NACK/disconnect, trust-bundle mismatch, and proxy/Cilium restart. Require an explicit identity or policy denial and zero application response where protection is required. Restore the dependency and prove that the authorized request recovers. A timeout without a correlated proxy/policy verdict is inconclusive. Test an unknown destination inside the protected mesh range on 80, 8080 and a high port: the current ztunnel outbound path can fall back to raw TCP passthrough when no workload/upstream resolves, so this must be changed to an explicit deny (with carefully scoped external/platform exceptions) before claiming that all protected traffic traverses authenticated ztunnel. Also test an empty effective ALLOW set: the inspected ztunnel policy semantics allow when no ALLOW policy exists, so requiring a client certificate alone does not implement authenticated-only authorization. Keep capture of inner payload separate from encrypted inter-node transport evidence; WireGuard/IPsec cannot substitute for workload mTLS.

### Evidence and test-double boundary

Record the source SHA and image ID actually running in each cluster, runtime architecture, test selection/pass/skip counts, request outcomes, authenticated peer identities, policy verdicts, xDS ACK/NACK state, and packet evidence. A packet trace must show the expected cross-node HBONE/TLS flow and must not expose application plaintext; a Grafana screenshot is taken only after load and supports, but never replaces, machine assertions. Keep failures and recovery output.

Synthetic remote-workload injection is permitted only as an isolated unit/integration diagnostic for mapper, stream and metric behavior. It must not be delivered through a production side channel, replace SPIRE/bundle/ClusterMesh provenance, or establish authorization or `Protected`. The remote xDS and policy path must be exercised using authenticated records from the native integration boundary. ACK, certificate issuance, namespace labels and dashboard values remain separate observations.

### Current enhanced-fork implementation gates

The active data-plane work is in the user's enhanced [`ephico2real2/cilium`](https://github.com/ephico2real2/cilium) fork, checkout `/private/tmp/cilium-ztunnel-authorization-runtime`, branch `feat/ztunnel-spire-credentials`, based on `f142e58d06a458b72cf7ea27999c093ca87c9c2b`. The source is currently dirty; record the exact final tree/commit before building an image. The currently deployed Observe image is an older fork build and must not be confused with this candidate.

The fork already has meaningful local ztunnel, ACK, lifecycle and authorization-transport enhancements, but this does not mean cross-cluster workload mTLS is complete. Source review found the ClusterMesh/ztunnel compatibility guard still rejects the combined profile; the current endpoint source wraps local CiliumEndpoint/CiliumEndpointSlice watchers; ClusterMesh connection lifecycle does not itself provide a remote workload record with authoritative Pod UID, service account and labels; and workload resource naming still needs cluster-qualified identity to prevent collisions. The new authorization xDS store transports compiled resources and records ACK metrics; it does not compile Cilium policy or provide an effective-policy admission barrier. Keep the guard until authenticated remote snapshots and deltas, cluster-qualified lifecycle, cryptographic cluster binding, effective policy, fail-closed unknown-destination handling and recovery tests are implemented against the fork's native interfaces.

The companion ztunnel candidate is `/private/tmp/cmtc-ztunnel-enforcement`, branch `feat/persistent-inbound-mtls`, with local edits based on `376218cf6f662b1c00fd9407ff8ee27b889cd56c`. Keep its local proxy fixes separate from upstream and pin the source actually used. Existing Rust tests confirm that no effective ALLOW policy means allow; this behavior must be changed or safely constrained for the authenticated-only mesh profile. Cilium remote identity publication, an ACK, and inbound certificate validation each prove different gates; no one result substitutes for the others.

### Review of the submitted architecture blueprint

Accepted: separate control-plane trust orchestration from native Cilium datapath/xDS; recognize that remote identity publication alone does not provide effective L4 authorization; test trust and policy failures closed; use the two-cluster mesh as an end-to-end fixture. Refined: first trace the existing native discovery and policy interfaces, then use mocks only for narrow diagnostics; do not add a CMTC-to-ztunnel injection path to avoid building the real integration. Verify SPIFFE federation and cluster binding against the selected trust-domain and issuer model rather than assuming that a common root or URI string distinguishes clusters. The blueprint's suggested PR order is advisory and remains subordinate to these security dependencies and the canonical agile backlog.
