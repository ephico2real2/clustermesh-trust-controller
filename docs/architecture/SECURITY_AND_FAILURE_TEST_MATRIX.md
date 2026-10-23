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
