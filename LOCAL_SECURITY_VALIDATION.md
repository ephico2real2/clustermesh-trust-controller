# Local mTLS and startup validation

This is an in-progress CMTC-101/403 qualification on the MacBook's isolated two-node `cmtc-mtls` fixture. CI and publication are deferred. The existing two Observe/ClusterMesh clusters are preserved. These results do not close the full CMTC security implementation or enable the Observe-only API's Strict mode.

## Exact deployed components

| Component | Qualified local source | Runtime |
| --- | --- | --- |
| Node ztunnel | `d79d3dfaef3d7afeb3552ea53cf90213141e95d3`, based on Cilium ztunnel `5bb9cf256b10a209ae9bc0624ddfbf27dbc439de` | `localhost/cmtc-ztunnel:strict-d79d3df-v2`; image config `9339a8f37174055c9b303748fc3bfcba14586997c0d82a49e70cbb9b8bb58946`; Rust 1.90, Linux ARM64 development build |
| Cilium agent | `63ce8231092cb97ac2ae2b66ed0bfe2d7cec11fd` | `localhost/cilium:zds-ack-local`; image config `05993214714e44ad4a6a6f29474aa8fbc158c545e920b7313511596ba311a282`; Go 1.27.1, Linux ARM64 |
| Chart strict command | `66cfc59f3e94dd11264f189fc62c0eaf3e9f7bff`, included in the agent branch | `proxy-mtls` when `encryption.ztunnel.requireMtls=true`; an explicit compatible proxy image is required |
| Proxy test-helper cleanup | `a1c3e9cd8f4b23128d70c434c4d01295fb252f9b` | Source/test-only follow-up; this commit is not the deployed proxy binary |

Both images were built with the MacBook host's Podman CLI against the task-owned Ubuntu connection, exported as archives and loaded into the existing kind runtime. The agent overlays its Go binary onto the qualified fork runtime/BPF base; this is not a fresh BPF build. Image config IDs above are local identities, not registry manifest digests. No AMD64 or release-performance qualification is implied.

Reproducible source patches are retained under [docs/development/patches](docs/development/patches/), with [proxy pins](docs/development/ztunnel-proxy.lock.json). The fork commits remain local while publication is deferred.

## Measured results

The proxy's strict process setting requires a verified inbound TLS identity before dynamic authorization. A workload's missing required policy reference denies access; an authenticated peer still cannot override an explicit DENY. The distinct command prevents an older binary from silently ignoring an unknown security setting.

| Local check | Observed output |
| --- | --- |
| Old pinned proxy with `proxy-mtls` | Exit 1, `unknown command: proxy-mtls` |
| Proxy authentication/RBAC unit tests | Three new authentication cases and three existing RBAC cases passed |
| Rust lint cleanup | Full benches/tests/bins Clippy passes with `-D warnings`, without the earlier category exceptions |
| Affected helper tests | Four CRI tests and eleven SPIRE tests passed |
| Test-selection guard | A nonexistent filter and an incorrect expected count both fail; the actual 4/11 selections pass |
| CLI/configuration matrix | Default and `proxy` remain compatible; environment opt-in works; `proxy-mtls` cannot be downgraded with `REQUIRE_INBOUND_MTLS=false`; invalid values fail before startup |
| Strict proxy with earlier agent `f052d127` | 57 path checks with the native rule and 57 with both nodes' dynamic/static policy caches empty; 2,666 continuous unauthenticated restart probes, zero HTTP responses; original rule restored |
| New agent `63ce823` with strict proxy | 57 present-policy and 57 empty-cache path checks; 2,581 continuous restart probes, zero unexpected HTTP responses; original policy restored |
| Fresh cross-node application load | 3,000/3,000 HTTP 200 through Service plus 3,000/3,000 through Pod IP; 600 unenrolled attempts rejected without HTTP response |
| Grafana | Native queries and the exclusive percentage denominator pass; both themes render; unimplemented planned signals remain explicitly unavailable |

Path checks cover application ports 80, 8080 and 9443, Service port 18080 translated to 8080, same-node and cross-node unenrolled sources, and both node hosts. No CNP, CCNP or Kubernetes NetworkPolicy is used to create these authentication results. The proxy unit cases additionally cover ports 1 and 65535. This is sampled port-independent logic, not an exhaustive network-path proof.

The CLI matrix only establishes parsing and effective configuration. It runs without workload credentials or a reachable CA/xDS dependency; its report explicitly has `deploymentReady=false`. Actual deployment and traffic acceptance come from the separate kind trials.

The original load attempt is retained as a diagnostic: Fortio's `-nocatchup` option skipped eight scheduled Pod-IP requests. All 2,992 issued requests returned HTTP 200, but the exact 3,000-request assertion correctly failed. Removing that option produced the qualified 6,000/6,000 result. An initial SPIRE test filter selected zero tests; it is also retained as invalid verification, followed by the actual eleven-test execution and a guard against recurrence.

## ZDS acknowledgment and lifecycle increment

The new Cilium agent requires an explicit successful ACK, rejects malformed/missing ACKs and unsupported protocol versions, and bounds queue/socket waits. Expired queued updates are discarded. Cancellation during an in-flight operation retires the connection because ZDS V1 has no request nonce. A replacement joins the previous handler before consuming updates. Cache state commits before success publication, and snapshot network waits no longer hold the cache mutex.

Local real-socket race tests cover ACK/NACK, missing ACK, malformed data, timeout/recovery, queue saturation, cancellation, late ACK rejection, next-update reuse, replacement during a stalled ACK and shutdown during hello/snapshot waits. The privileged network namespace, iptables and rolling-update cases pass together with repository lint and Go vet. Structured logs identify actual acknowledged endpoint enrollment and its elapsed duration. An ACK alone does not prove SVID validity, policy convergence or protection.

Research and complete proposed code are tracked in [issue #11](https://github.com/ephico2real2/clustermesh-trust-controller/issues/11) and [issue #12](https://github.com/ephico2real2/clustermesh-trust-controller/issues/12). The primary agent reviews proposals and tests selected changes locally. One proposed metadata-before-capture ordering was rejected because the current void enrollment callback could allow CNI success without installing a hold; the revised proposal preserves capture before conversion failure.

## Packet and Grafana evidence

Ten canary-bearing application requests succeeded during the recorded VXLAN capture. It contains 19,038 packet observations, including 14,538 inner-TCP-port-15008 observations. A TLS-record-header check identified 9,724 application-data, four handshake-record and two change-cipher-spec packet observations. The canary was absent from individual packet bytes. These are packet observations, including duplicates, not TLS handshake totals. The filter does not cover every possible route, and per-packet searching does not replace TCP stream reassembly or a plaintext detection control.

The screenshots show the fresh 6,000-request/600-rejection load window. Their older explanatory text also references the preceding qualified trial; exact source/window/request results for this increment are recorded above and in the raw bundle. Native counter increases are estimates and include scrape/window effects; they are not exact HTTP request totals. Planned panels intentionally retain their unavailable state.

![Workload Security after local load, dark theme](docs/images/persistent-authenticated-only-dark.png)

[Light-theme screenshot](docs/images/persistent-authenticated-only-light.png)

Raw local commands, failed and passing logs, image/source evidence, empty-cache snapshots, traffic output, packet captures, query vectors and screenshots are retained at `/private/tmp/cmtc-ztunnel-build-tools/`. No root private key or workload credential is included in this evidence. Publication remains deferred.

## Remaining acceptance

The next local increment addresses reenrollment after a failed DEL: cached enrollment cannot substitute for installed capture and a fresh ACK. Concurrent capture removal and intent transitions still require a generation-aware state machine. Endpoint creation must propagate enrollment failure before application startup, and running-pod enrollment needs a separate capture transition gate.

Both runtime tests of a copied proxy app label were denied after enrollment. Source review explains why: the current helper looks up `k8s:app`, while canonical label maps use `app`. Do not activate a label-spoofable exclusion by merely correcting that key. Remove the unnecessary host-network-proxy exemption after qualification, or use authoritative identity if one is required.

Effective workload-bound authorization, namespace/Pod UID freshness, authenticated remote discovery and cluster identity, trust lifecycle, independent WireGuard/IPsec evidence and platform safety remain open. The ClusterMesh compatibility guard and Observe-only API remain in place. Continue through [delivery status](docs/agile/DELIVERY_STATUS.md) and the canonical backlog; this increment is not project completion.
