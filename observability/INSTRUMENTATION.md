# CMTC instrumentation ownership

Status: implementation in progress, 2026-10-25. The user permits Opus to improve instrumentation from first principles. The existing [metric contracts](metrics.json) and [31 capability goals](capabilities.json) remain the acceptance baseline.

Start with the event or state. Identify the component that can observe it. Select its metric type and lifecycle. Then select the query and chart. Record any change to a contract's meaning before replacing it.

## Current collection

The local query at `2026-10-25T12:38:49Z` returned 205 metric names and 1,658 series from six CMTC targets. The earlier full inventory groups those names into 181 families. These totals include controller-runtime and process metrics. They do not mean that 205 security capabilities work.

The same query returned no ztunnel targets or native TLS series. Ztunnel is off in both clusters. The source-tested collectors below therefore remain planned for live qualification. See [the saved query results](../docs/evidence/metrics-instrumentation/current-queries.json) and [query validation](../docs/evidence/metrics-instrumentation/README.md).

Each cluster scrapes its local exporters. Cluster B remote-writes to cluster A. Grafana queries that central source. Preserve the cluster and node labels. Add no separate CMTC metrics aggregator.

## Component owners

| Question | Observing component | Contract and boundary |
| --- | --- | --- |
| What was selected or observed? | CMTC controller and node agent | `cmtc_namespace_decisions`, namespace counts and `cmtc_pods_observed` measure intent and inventory. `internal/telemetry/metrics.go` defines them. |
| What did the prototype hook observe or drop? | Opt-in CMTC eBPF DaemonSet | The six `cmtc_datapath_*` families measure the audited hook and its freshness. Packets are separate from connections and TLS. |
| Was remote identity found? | Cilium native remote workload discovery | Count a cache miss at an actual authenticated lookup. Track invalidation and recovery at the source/session owner. An unknown identity cannot become a plaintext fallback. |
| Did TLS verify the peer? | Ztunnel TLS accept/connect owner | Use the three native TLS families below. The destination verifies the client; the source verifies the server. |
| Did effective policy deny a connection? | Ztunnel destination authorization check | Use the native destination `DENY` result for the authorization-denial contract. A rejected TCP attempt is separate from a TLS verification failure. |
| Did SPIRE acknowledge a registration change? | Experimental registrar | Instrument the actual RPC and verified readback in `internal/spireregistrar/runner.go`. Retries, completed changes and withdrawal acknowledgments are separate events. Readback does not prove workload issuance. |
| Is SPIRE usable now? | Authenticated SPIRE client | `cmtc_spire_ready` needs a fresh authenticated response at the specified API boundary. Registrar process readiness cannot supply this claim. |
| Was the approved trust generation consumed? | Cilium/ztunnel trust verifier | `cmtc_trust_bundle_ready` needs verified consumer state and freshness. The public issuer-profile producer proves publication only. |
| Are pods protected, pending or failed? | Enforcement state owner | These gauges need mutually exclusive current Pod states, exact incarnation and fresh capture, identity and effective-policy gates. Neither inventory nor an ACK supplies them. |
| Does node encryption work with workload TLS? | Transport and controlled traffic verifiers | Compatibility, dual-encryption, MTU and transport-failure contracts need their own controlled probes. Keep WireGuard/IPsec separate from workload TLS. |
| Did a dependency, rollout or rotation fail? | The component that performs that operation | Instrument the actual attempt or state transition. Define whether retries count attempts or one incident. Preserve platform safety. |

An owner row is an implementation assignment. It does not mark an unfinished collector or security gate complete.

## Source-tested TLS collectors

The ztunnel recovery commit is `35a6c9403eb5c00b1b79aafe2851f423cd195540`. Its native owner is `src/tls/profile_provider.rs`. The recorded qualification passes 533 library, 20 direct, 30 namespace and two diagnostic tests, with formatting and strict Clippy. Those tests qualify source behavior. They do not qualify a running proxy or ClusterMesh traffic.

| Contract | Emitted family | Query boundary |
| --- | --- | --- |
| `cmtc_mtls_handshakes_total` | `istio_tls_handshakes_total` | Select `reporter="destination"`; rate or increase by result. |
| `cmtc_mtls_handshake_duration_seconds` | `istio_tls_handshake_duration_seconds` | Select destination buckets; aggregate by cluster/le before calculating a percentile. Successful handshakes only. |
| `cmtc_mtls_active_connections` | `istio_tls_connections_active` | Select destination; use the current gauge. A pooled TLS transport counts once. |
| `cmtc_mtls_identity_validation_failures_total` | `istio_tls_handshakes_total` | Select `result="peer_verification_failed"`; count each local verifier's rejection in its owning cluster. |

These are mappings to real emitted families. They do not create duplicate `cmtc_*` exporters or recording rules.

A TLS handshake is separate from a TCP connection, an HBONE stream and an HTTP request. Reuse of a pooled TLS connection creates no additional handshake. The active-session gauge can decrease on authority invalidation before the socket closes. It is a count of verified sessions owned by the proxy, not a count of application requests.

TLS 1.3 can complete the client's handshake before the server rejects the client certificate. Use destination results for the server's client-identity decision. The identity-failure contract also retains source-side server-verification failures. It counts verifier events and is not a slice of a unique-connection pie.

## Label and lifecycle rules

Use code-owned result and stage enums. Keep Pod UIDs, IPs, SPIFFE IDs, certificate serials and error strings in structured logs. Supply cluster/node identity through the established scrape path. Do not add both reporters when counting one transport.

Counters reset with their owning process unless their source explicitly persists in a kernel map. Use `rate()` or `increase()`. Gauges describe current state and need no rate. Timestamp gauges need an age or deadline comparison. A histogram without samples has no percentile.

Expose real idle zeros only when the collector exists and is fresh. Keep an absent exporter unavailable. A failed scrape, stale lease or missing required node must not become a successful zero or an aggregate pass.

## Qualification sequence

1. Add the collector at the actual event owner.
2. Test success, rejection, idle, cancellation and recovery semantics.
3. Run the component against the owned clusters.
4. Verify its declared metric types and bounded labels.
5. Verify all expected node targets and remote-write freshness.
6. Run positive and negative traffic in both directions.
7. Validate the real PromQL queries.
8. Capture both dashboard themes during measured load.
9. Package the verified source with host Podman.
10. Repeat affected checks with the exact deployed images.
11. Update the contract's runtime qualification.

The two consolidated dashboards retain all nine historical domains. Activate each planned section as its owner passes these gates. Keep the [delivery status](../docs/agile/DELIVERY_STATUS.md) and [security acceptance matrix](../docs/architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md) authoritative for protection claims.
