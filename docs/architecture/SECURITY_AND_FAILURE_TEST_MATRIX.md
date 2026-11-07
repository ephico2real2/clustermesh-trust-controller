# Security, encryption and failure test matrix

<!-- CMTC_DOC_CONTEXT -->
Design scope: proposed behavior requires the stated acceptance tests. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This matrix is the acceptance contract for workload mTLS across ClusterMesh. Revised 2026-10-25 with the first live
traffic results. A row passes only with recorded versions, topology, identity and policy expectations, and
independent packet or transport evidence. Unit tests and live tests are separate results.

## Current results (2026-10-25, 23:00–23:10Z)

**Scope.** Clusters `kind-cmtc-a` and `kind-cmtc-b`. Cilium agents built from our fork at `6090aa6eff`, ztunnel from
our fork at `f221f29b59`, SPIRE node agent from our fork at `0f8fe4d681`. Exact image pins are in
[delivery status](../agile/DELIVERY_STATUS.md). The fixture is the enrolled namespace `cmtc-live-mtls` (two clients
and two servers per cluster, one of each per node) and the negative namespace `cmtc-live-mtls-unauth`. No
CiliumNetworkPolicy applies, so both native policy maps allow all peers. Ports: 80, 8080 and 31337.

Evidence: [G1 destination sources](../evidence/g1-destination-sources/README.md) (probe rows in `probes/`,
ClusterIP, DNS and gauge reads in `clusterip-dns-gauges.txt`).

| From | Same node | Cross node | Cross cluster (Pod IP) | Global Service by ClusterIP | Global Service by name | Unregistered caller |
| --- | --- | --- | --- | --- | --- | --- |
| cmtc-a | 6/6 allowed | 6/6 allowed | 12/12 allowed | 6/6 allowed | **Fail:** DNS timeout | 6/6 no response |
| cmtc-b | 6/6 allowed | 6/6 allowed | 12/12 allowed | 6/6 allowed | **Fail:** DNS timeout | 6/6 no response |

- Every allowed reply named the expected serving cluster.
- The unregistered caller's six attempts per cluster ended in a curl connect timeout (rc 28). No per-request policy
  verdict was correlated, so the explicit-denial row below stays open.
- Admission state: after convergence (23:00:08Z) every agent's
  `cilium_ztunnel_xds_effective_policy_sources` gauge reads node=2, cluster=2, peer=4. Each destination plan has 7
  rules. No plan was republished afterwards.

**Before the change** (agents at `6a00282808`, 22:57Z): same-node 6/6 allowed; cross-node and cross-cluster reset
(curl rc 56). The destination ztunnel logged `no allow policies matched`. [ADR-010](adr/ADR-010.md) describes the
cause and the fix.

**What these results prove.** Traffic outcomes for the allow paths, and the agents' admission state from logs and
metrics.

**What they do not prove.**

- Per-connection peer-certificate evidence. The runner prints `securityReasonVerified: false`; ztunnel logs and
  certificates were not correlated per request.
- WireGuard or IPsec transport encryption. Neither is configured.
- Any recovery behavior.
- Denial by policy. The fixture runs with default allow.
- `Protected` status for any workload.

## Open gates

Each gate stays open until its own evidence passes on the deployed build.

1. **DNS from enrolled Pods fails, in both clusters.** From the enrolled `client-worker`, `nslookup` to kube-dns
   (`10.11.0.10`, `10.21.0.10`) returns "no servers could be reached"; unenrolled Pods in both clusters resolve
   ([record](../evidence/g1-destination-sources/clusterip-dns-gauges.txt)). Diagnosed: `cilium-dbg monitor` shows
   the query dropped at the source endpoint's egress (`bpf_lxc.c:1626`, UDP to a CoreDNS backend on port 53), by the
   HBONE-only gate, which has no resolver exception. A fix is in progress and not deployed. It blocks the Global
   Service by name.
2. **Recovery on `6090aa6eff` not run:** agent restart, ztunnel restart, node reboot, drain and F1 lost-ACK recovery.
   Risk to test: after an agent restart the destination can publish a plan before it reads the external sources
   again, which could close established cross-cluster connections.
3. **ADR-010 review findings (OB3), not fixed:**
   - C2: one compromised agent can make every reader invalid (a forged duplicate Pod UID; 33 epochs or 1,024 node
     names).
   - C3: expiry starts when the record is received, so a reader restart plus a partition allows up to two lease
     TTLs. Floors are never pruned.
   - C4: narrowed egress takes up to 30 s, not 5 s, because egress is sampled after serial revalidation.
   - C6: an agent that crash-loops past 32 epochs leaves readers invalid until each restarts. More than 64 sources,
     512 cuts or 4,096 ports makes a destination deny every caller.
   - C7: size bounds stay plan-fatal.
   - C8: risks only. The record worst case is 888,391 of 1,048,576 bytes. Each 5 s refresh rewrites the whole record,
     so etcd history grows (estimate, not measured).
4. **Transport encryption.** WireGuard or IPsec beneath workload TLS is not configured or qualified.
5. **Policy shapes.** A source whose egress denies the destination, and live port narrowing, are unit-tested only
   (`pkg/ztunnel/xds/effective_sources_test.go` in the Cilium fork).
6. **Per-connection evidence.** Correlate each allowed request with the verified client and server SPIFFE IDs.
7. **Every row marked "Not run" in the matrix below.**

## Scenario matrix

The primary profile requires workload mTLS plus WireGuard or IPsec on the same cross-cluster flow. The
[existing lab review](../research/EXISTING_LAB_REVIEW.md) records historical failures to reproduce. A report that
exits zero while printing trouble is not a pass: negative checks fail the qualification job.

| Scenario | Expected behavior | Evidence | State, 2026-10-25 |
| --- | --- | --- | --- |
| App A → App B across clusters, no WireGuard/IPsec | Valid SPIFFE identities, HBONE TLS, policy enforced | TLS peer identity, traffic trace, denial tests | Allow paths pass both directions; peer identity per request and denials not recorded |
| Same path over WireGuard | mTLS plus node encryption, no plaintext fallback | ztunnel metrics, WireGuard peer state, packet capture | Not run |
| Same path over IPsec | mTLS plus XFRM transport protection | TLS metrics, XFRM state, packet capture | Not run |
| mTLS off, WireGuard/IPsec on or off | Supported ClusterMesh behavior unchanged | Baseline connectivity suite | Not run on the current build |
| Unknown remote identity | Protected connection refused | Authentication failure, denied flow | Not run |
| Forged foreign-cluster SPIFFE URI | Unauthorized identity refused despite the common root | Negative SVID test | Source tests only |
| Excluded namespace → protected namespace | Denied unless explicitly authorized | Packet capture and policy verdict | Unregistered caller: no response; verdict not correlated |
| New or relabelled Pod before ztunnel is ready | No unprotected connection | Race stress test | Not run on the current build |
| Missing SVID or SPIRE down | No new unauthenticated protected connection | Chaos test | Not run on the current build |
| Hub partition or trust bundle drift | Cached verified trust where safe; no unsafe CA retirement | Digest, readiness, partition test | Not run |
| Root rotation, old and new overlap | New SVIDs work everywhere before the old root is removed | End-to-end handshake matrix | Not run |
| WireGuard key missing or IPsec XFRM stale | No silent transport downgrade when required | Kernel and flow inspection | Not applicable until the transport is configured |
| DNS UDP/TCP, API, webhook, kubelet | Control-plane communication stays functional | Probes, cluster health | **Fail:** DNS from enrolled Pods |
| OpenShift operator upgrades, hosted control plane | No unsafe enrollment or degradation | ClusterOperator conditions, operator tests | Not run |
| Node reboot, Cilium upgrade, ztunnel crash | Safe reconvergence, fail-closed posture | Restart tests | Not run on `6090aa6eff` |
| MTU and service translation | No hidden fragmentation or routing regression | p95/p99 latency, MTU captures | Not run |

**Release gate.** An encrypted connection is not proof of authorization. A namespace label is not proof of
enforcement. No production support claim without negative security tests.

## Two-cluster test design

### Topology and positive path

Install the same application identity (namespace, service account, labels and image) in both clusters, with a local
client in each. Give the backends distinguishable responses, so each reply names the serving cluster. The
`cmtc-live-mtls` fixture does this with the `X-CMTC-Cluster` response header. Assert separately:

| Caller | Destination | Expected result | State |
| --- | --- | --- | --- |
| Cluster A client | A backend | Local path succeeds | Passes |
| Cluster A client | B backend | Cross-cluster authenticated request succeeds | Passes (outcome; peer identity per request not recorded) |
| Cluster B client | B backend | Local path succeeds | Passes |
| Cluster B client | A backend | Reverse cross-cluster request succeeds | Passes (outcome; peer identity per request not recorded) |

Keep Service VIP and direct Pod IP tests separate. Exercise TCP 80, 8080 and a high port such as 31337. The high port
probes port independence; it is not an allowlist. Policy attaches to workload identity and the original application
tuple, never to a guessed port list or the HBONE port. Under load, keep per-direction request totals, the verified
client and server SPIFFE IDs, the ztunnel decision, xDS resource state and packet captures from the same run.

### Negative and recovery path

For both directions, test:

- a non-enrolled client and an invalid-SVID client;
- an unauthorized cluster identity;
- an allowed identity on a denied application port;
- a source whose egress denies the destination;
- missing or stale policy, xDS NACK and disconnect;
- a trust-bundle mismatch;
- proxy and Cilium restart.

Each case needs an explicit identity or policy denial and no application response. A timeout without a correlated
proxy or policy verdict is inconclusive. Restore the dependency and prove that the authorized request recovers.

Two upstream ztunnel behaviors are changed in our fork and must be tested live:

- **Unknown destination inside the mesh.** Upstream can fall back to raw TCP passthrough. With
  `REQUIRE_MESH_HBONE=true`, the fork refuses an unknown protected destination and any egress without an explicit
  exception (`src/proxy/outbound.rs:787-803`). Test 80, 8080 and a high port.
- **Empty effective ALLOW set.** Upstream allows when no ALLOW policy exists. With `REQUIRE_INBOUND_MTLS=true`, the
  fork denies a protected workload that has no effective ALLOW policy (`src/state.rs:762-768`).

Keep inner-payload capture separate from inter-node transport evidence. WireGuard or IPsec cannot replace workload
mTLS.

### Evidence and test-double boundary

Record the source SHA and image ID running in each cluster, the architecture, test selection, pass and skip counts,
request outcomes, authenticated peer identities, policy verdicts, xDS ACK/NACK state and packet evidence. A packet
trace shows the expected HBONE/TLS flow and no application plaintext. A Grafana screenshot is taken after load; it
supports, but never replaces, machine assertions. Keep failures and recovery output.

Synthetic remote-workload injection is allowed only as an isolated unit or integration diagnostic. It never uses a
production side channel, never replaces SPIRE, bundle or ClusterMesh provenance, and never establishes authorization
or `Protected`. The remote xDS and policy path is exercised with authenticated records from the native integration
boundary.

### WireGuard and IPsec composition

Only after the workload-mTLS profile passes, a separate matrix composes WireGuard and then IPsec with the same flow.
Verify workload TLS identity and node-layer encryption independently in each run. Never infer one layer from the
other, from a successful request or from a dashboard.

## History

- **2026-10-23:** this page listed acceptance targets only; none had run.
- **2026-10-24:** it added the enhanced-fork implementation sequence (finish the xDS contract, make origin and
  resource identity unambiguous, atomic synchronization, use the Cilium policy result, keep the compatibility guard,
  build exact paired images) and Go sketches for `WorkloadOrigin`, `ClusterTrustMap` and `PolicyAckBarrier`. Those
  steps are now implemented in the forks in their own form: the blanket ClusterMesh/ztunnel rejection is replaced by
  a capability check (`pkg/ztunnel/cell.go:73` in the Cilium fork), and quarantine release is tied to ACKs on the
  current ADS stream. The checkouts and pins that section named (`f142e58d06`, `376218cf6f`) are historical. Read
  the earlier text in git history.
- **2026-10-24, blueprint review:** the user's architecture blueprint was accepted as a test-design input. Its
  ownership split stands. Its Cilium v1.20.4 pin does not describe the fork work.
