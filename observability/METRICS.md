# CMTC metric meanings and presentation

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This contract separates implemented collectors from planned story outputs. A planned type is a design proposal, not a claim that a live exporter exists. The original nine domains and all 31 proposed metric names remain mapped in [capabilities.json](capabilities.json).

The chart follows the value's meaning: gauges are current levels/states, counters become rates or selected-range increases, and latency percentiles come from real histogram buckets. A pie is used only for mutually exclusive categories that exhaust one denominator. No missing security metric is converted to a successful zero.

Read [the instrumentation plan](INSTRUMENTATION.md) for component ownership, source-tested TLS collectors and the live collection gates. A collector can pass source tests while its dashboard contract remains planned.

## Implemented collectors

| Metric | Type | Meaning | Presentation / owner |
| --- | --- | --- | --- |
| `cmtc_enforcement_available` | gauge | Whether CMTC can verify required datapath enforcement; always 0 in Observe mode. | Mapped Unavailable status for observed zero; missing telemetry stays unavailable. Owner: CMTC controller. |
| `cmtc_namespace_decisions` | gauge | Current mutually exclusive selected/excluded/platform/unselected namespace decisions. | Latest table and one pie of all observed namespaces; categories must exhaust one denominator. Owner: CMTC controller. |
| `cmtc_namespaces_eligible` | gauge | Observed non-platform namespaces, including explicit exclusions. | Latest count/table; not safe-to-enroll or protection coverage. Owner: CMTC controller. |
| `cmtc_namespaces_enrolled` | gauge | Namespaces bearing the enrollment label from any actor. | Latest count/table; never label it protected. Owner: CMTC controller. |
| `cmtc_namespaces_selected` | gauge | Current namespace policy selection intent; Observe does not mutate labels. | Latest count/table; not encrypted or protected namespaces. Owner: CMTC controller. |
| `cmtc_node_agent_ready` | gauge | Successful local inventory observation, 0/1 per node. | Latest count/table; not enforcement readiness. Owner: CMTC node agent. |
| `cmtc_pods_observed` | gauge | Node-local pod inventory split by pod/host network category. | Latest table by cluster/node/network; no protection inference. Owner: CMTC node agent. |
| `cmtc_policy_evaluations_total` | counter | Successful namespace policy evaluations. | Evaluations/s over $__rate_interval, grouped by cluster. Owner: CMTC controller. |
| `controller_runtime_reconcile_errors_total` | counter | Actual controller-runtime reconcile error observations. | Errors/s over $__rate_interval; observed zero is valid. Owner: controller-runtime. |
| `controller_runtime_reconcile_time_seconds` | histogram | Observed controller reconcile duration in seconds. | p95 from bucket rates aggregated by cluster/le; not TLS/network latency. Owner: controller-runtime. |

## Opt-in datapath prototype collectors

These six implemented source collectors are separate from the 31 original proposed security names. They do not fulfill planned TLS, protected-pod, remote identity, authorization or node-encryption contracts. The profiles are qualified sequentially; the run ledger identifies which one is installed. An uninstalled profile remains absent. Each exporter has bounded `cluster`, `node`, `direction` labels, with one audited veth/hook per selected node. No namespace, Pod UID, SPIFFE ID or certificate label is added.

| Family | Type | Observation boundary and lifecycle |
| --- | --- | --- |
| `cmtc_datapath_observer_packets_total` | counter | Packets seen at the one audited TCX hook before the native Cilium verdict; not forwarded packets, attempts, requests, TLS handshakes or mTLS. Packets/s or selected-range increase; observer process/attachment restart resets the counter. |
| `cmtc_datapath_observer_bytes_total` | counter | skb byte lengths seen at the audited TCX hook before the native Cilium verdict; not application payload bytes. Bytes/s or selected-range increase; no encryption inference. |
| `cmtc_datapath_observer_ready` | gauge | Fresh sample verifies the exact audited observer interface and native baseline chain. Zero is unverified, not an enforcement verdict. Latest per-cluster/node/direction state; absence remains unavailable. Observer counters are omitted when this is stale or zero. |
| `cmtc_datapath_fence_dropped_packets_total` | counter | Packets rejected by the explicit deny-only audited TCX hook; retransmits and non-HTTP traffic count separately. Packets/s and selected-range increase; never requests, connections, TLS failures or protection coverage. Counter persists across exact pinned-map adoption, resets on a new attachment/map. |
| `cmtc_datapath_fence_dropped_bytes_total` | counter | skb byte lengths rejected by the deny-only audited TCX hook; not application payload or encrypted bytes. Bytes/s or selected-range increase; same pinned-map lifecycle as dropped packets. |
| `cmtc_datapath_fence_quarantine_verified` | gauge | A sample no older than 3 seconds verifies the exact committed deny attachment and frozen audited native chain. This is never Protected, mTLS or first-packet admission. Latest per-cluster/node/direction state: 1 quarantine verified, 0 unverified; absent/down scrape stays unavailable. Counters omitted when unverified. |

Fence counters live in the committed pinned kernel map, survive SIGKILL and exact adoption, and can reset after defunct retirement/new-map installation. The observer's unpinned attachment/maps reset when its process/attachment restarts. Prometheus `rate`/`increase` handle observed resets, but cannot recover increments during a missing scrape interval or distinguish an unseen complete map replacement. Keep evidence of exact map IDs and traffic-boundary samples in the lab ledger.

Both exporters suppress packet/byte counters when their sample is stale/unverified and emit readiness 0. A successful HTTP scrape is only reachability: check `up`, the verification gauge and actual counters separately. An idle fresh attachment legitimately exports zero counters/rates; an absent source produces no series and must never be filled with `vector(0)`. With the lab's 5s scrape interval, allow bounded scrape visibility lag in addition to the exporter's 3s freshness bound; Prometheus lookback is not a substitute for freshness. The local validator checks each source Targets API and requires central `timestamp(metric)` samples within 15 seconds; the instant-vector evaluation timestamp alone cannot prove remote-write freshness.

The optional fence and observer listeners expose only GET `/metrics` on the exact downward node address at ports 18084 and 18085 respectively. Loopback health is separate. This lab HTTP surface is not authenticated and requires explicit operator opt-in; no API credentials, health handler, configuration endpoint, pprof, hostPID or additional privileges are added. It is not a production scrape-access policy.

## Planned story contracts

| Proposed metric | Intended type | Meaning | Presentation / owner |
| --- | --- | --- | --- |
| `cmtc_apiserver_probe_success` | gauge | Latest fresh safe API connectivity/TLS probe result. | Mapped latest state/history; not application mTLS or cluster-wide health. Owner: CMTC platform probe. |
| `cmtc_certificate_rotation_failures_total` | counter | Failed certificate rotation attempts or terminal failures with an agreed retry/event boundary. | Failures/s and range increase; retries must not silently multiply terminal failure counts. Owner: CMTC rotation controller. |
| `cmtc_cluster_ready` | gauge | All required verified cluster gates satisfied for the current generation and freshness window. | Mapped status/table; no sum that hides one failed or missing required gate. Owner: CMTC cluster controller. |
| `cmtc_dual_encryption_probe_success` | gauge | Latest fresh controlled probe verifies both workload mTLS and the configured node encryption layer. | Mapped latest probe and state history; absence/staleness is unknown. Owner: CMTC transport probe. |
| `cmtc_issuer_ready` | gauge | Expected issuer can provide a verifiable chain under a defined freshness/issuance check. | Mapped state/history; pod Ready or Issuer object presence is insufficient. Owner: CMTC issuer verifier. |
| `cmtc_mtls_active_connections` | gauge | Live verified TLS sessions owned by the destination proxy; a pooled transport is one session. | Uses istio_tls_connections_active{reporter="destination"}; latest value, no rate() or source-plus-destination sum. Source-tested; live collection pending. Owner: ztunnel TLS stream lifecycle. |
| `cmtc_mtls_authorization_denials_total` | counter | Destination policy rejections at the authorization boundary. | rate() or range increase, split from identity failures and attempts; avoid double counting. Owner: Cilium/ztunnel authorization. |
| `cmtc_mtls_handshake_duration_seconds` | histogram | Duration of successful verified workload TLS handshakes at the destination. | Uses destination-reported istio_tls_handshake_duration_seconds buckets; p95/p99 by cluster/le. Failed handshakes are excluded. Source-tested; live collection pending. Owner: ztunnel TLS boundary. |
| `cmtc_mtls_handshakes_total` | counter | Completed TLS handshake observations at the destination, split by a closed result set. | Uses destination-reported istio_tls_handshakes_total; rate() or selected-range increase. Source-tested; live collection pending. Owner: ztunnel TLS boundary. |
| `cmtc_mtls_identity_validation_failures_total` | counter | Local peer-verification rejections at either TLS verifier, grouped by its cluster. | Uses istio_tls_handshakes_total{result="peer_verification_failed"}; verifier events, not a unique-connection denominator. Source-tested; live collection pending. Owner: ztunnel peer verifier. |
| `cmtc_mtu_validation_failures_total` | counter | Failed controlled MTU/MSS validation attempts for the selected encryption profile. | Failures/s or range increase; preserve attempted-probe denominator separately. Owner: CMTC transport probe. |
| `cmtc_namespace_label_drift_total` | counter | Detected enrollment-label drift episodes under a defined deduplication boundary. | Event rate/range increase; not the number of namespaces currently drifting. Owner: CMTC enrollment controller. |
| `cmtc_namespace_policy_conflicts_total` | counter | Detected policy-conflict events under a defined deduplication boundary. | Event rate/range increase; current conflict state needs its own gauge/condition. Owner: CMTC policy controller. |
| `cmtc_namespaces_excluded` | gauge | Current explicitly excluded namespaces. | Latest count; current view uses namespace_decisions{decision="excluded"}. Owner: CMTC controller. |
| `cmtc_node_config_drift_total` | counter | Detected node desired/applied configuration drift episodes. | Event rate/range increase; current drift is a distinct status. Owner: CMTC node verifier. |
| `cmtc_plaintext_bypass_detected_total` | counter | A verifier observes unauthorized plaintext reaching a destination that requires mTLS. | Incident rate/count; a plaintext attempt rejected by DENY is not a bypass. Owner: CMTC traffic verifier. |
| `cmtc_platform_dependency_healthy` | gauge | Latest fresh platform dependency check, with a bounded dependency label. | Mapped table/status history per required dependency; missing dependency cannot pass aggregate readiness. Owner: CMTC platform verifier. |
| `cmtc_pods_enforcement_failed` | gauge | Current eligible pods in a failed enforcement state, not cumulative failure events. | Latest state count/table; never rate() this gauge. Owner: CMTC enforcement verifier. |
| `cmtc_pods_pending` | gauge | Eligible current pods awaiting one or more required enforcement gates. | Latest state count/table; exclusive with protected/failed states. Owner: CMTC enforcement verifier. |
| `cmtc_pods_protected` | gauge | Eligible current pods with fresh verified mandatory capture, identity and destination enforcement. | Latest state count/table; no inference from enrollment or ACK. Owner: CMTC enforcement verifier. |
| `cmtc_reconcile_errors_total` | counter | CMTC reconcile error events with a defined owner and retry counting boundary. | Errors/s; current view uses actual controller_runtime_reconcile_errors_total instead of inventing an alias. Owner: CMTC controller. |
| `cmtc_remote_identity_cache_misses_total` | counter | Lookup misses in the authenticated remote workload identity cache. | Misses/s; a miss alone is neither a rejected request nor a security breach. Owner: Cilium remote discovery. |
| `cmtc_rollout_aborted_total` | counter | Aborted rollout events with bounded reason/profile labels. | Aborts/s or selected-range increase; distinguish current rollout state. Owner: CMTC rollout controller. |
| `cmtc_spire_ready` | gauge | Fresh authenticated SPIRE API readiness acknowledgment at a defined boundary. | Mapped state/history; separate API ACK from registration and workload issuance. Owner: CMTC/Cilium SPIRE client. |
| `cmtc_transport_compatibility_ready` | gauge | Selected Cilium/ClusterMesh/ztunnel/transport profile passes the required compatibility gates. | Mapped status/table per profile; not a count of encrypted packets. Owner: CMTC transport verifier. |
| `cmtc_transport_encryption_failures_total` | counter | Observed required node-layer encryption failures at a defined probe/datapath boundary. | Failures/s by bounded profile/reason; not an application TLS handshake counter. Owner: Cilium/CMTC transport verifier. |
| `cmtc_trust_bundle_ready` | gauge | Required public bundle observed and consumed at the expected generation/digest with freshness. | Mapped state/table; ConfigMap existence alone is insufficient. Owner: CMTC trust verifier. |
| `cmtc_ztunnel_ready` | gauge | Fresh proxy-process/configuration readiness at a stated boundary. | Mapped table/status history; proxy readiness alone does not establish Protected. Owner: Cilium/CMTC proxy verifier. |

## Naming correction to settle before instrumentation

| Proposed metric | Intended type | Meaning | Presentation / owner |
| --- | --- | --- | --- |
| `cmtc_hostnetwork_pods_total` | gauge | Current hostNetwork pod inventory; the old proposed _total suffix is misleading for a level. | Use cmtc_pods_observed{network="host"} now; agree a gauge name before adding another exporter. Never rate() inventory. Owner: CMTC node agent. |

## Required telemetry in every owning security story

The collector, event owner and collection/query evidence ship with the story; no applicable mTLS, trust, authorization or recovery story is complete while its telemetry remains an unqualified placeholder. Specify the actual observing boundary, Prometheus type/base unit, bounded labels, reset/event/retry semantics and freshness before implementation. Collect real positive, negative, idle and missing-source cases, then validate queries and real traffic/load with both-theme screenshots in the existing two consolidated dashboards. Retain raw scrape/target/query/log/traffic outputs; source-only instrumentation is not qualified collection.

Actual TLS handshakes belong at the TLS boundary; certificate/peer checks at their verifier; authorization denials at the effective destination check; trust consumption/rotation at its authenticated bundle/issuer owner; retry/recovery at the actual lifecycle transition. The per-node observer/fence packet counters cannot substitute for any of those owners. ACKs, Ready, counters and enrollment intent cannot establish Protected. Preserve unimplemented original contracts as planned until the corresponding story passes its gates.

## Acceptance when a story delivers instrumentation

- Confirm the exporter's declared type, units, event boundary, labels and owner on a real scrape; update this contract and inventory.
- Define freshness, restart/reset semantics, a bounded label budget and the behavior for missing sources or no observations.
- Run the real query with success, failure, idle and absent-source cases. A percentile with no samples is unavailable; no eligible traffic has no meaningful success percentage.
- Preserve per-cluster identity and required-gate failures; gauges across overlapping reporters and TCP opens/HTTP requests/TLS handshakes must not be mixed.
- Capture the consolidated section under real relevant load in both themes. Activate and qualify the retained planned panel in its assigned section as the story lands.
- Keep pending/protected/failed pod states mutually exclusive before deriving coverage. Identity/certificate serial/pod-UID detail belongs in logs or bounded drilldowns, not new unbounded CMTC labels.

Reference presentation: [MongoDB chart dashboard rationale](https://github.com/ephico2real2/mongodb-poc/blob/main/chart/mongodb-search-helm/README.md#dashboards) and the pinned [diagram-kit dashboard skill](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/skill/dashboard/SKILL.md).

## Public issuer-profile producer telemetry proposal

The optional producer owns four implemented metrics, qualified with the exact source7e606195f5 image, real API failure/recovery tests, local scrapes on both mesh clusters and fresh B-to-A remote-write evidence in `docs/evidence/issuer-profile-producer/`: validation_attempts_total, publication_writes_total, source_checked_timestamp_seconds, and acknowledged_valid_until_timestamp_seconds, all prefixed cmtc_issuer_profile_. Only the existing configured cluster is a constant label; result/state are closed code-owned enums. Source name, UID, trust domain, certificate fingerprint, generation, error text and publication sequence stay in public output/structured logs rather than unbounded metric labels.

Validation counts complete producer-pass attempts, including retries; it is not incident deduplication. Publication writes count API responses, not globally unique commits: an API timeout after server commit is an error response, and retry re-reads the committed sequence instead of writing again. An unchanged pass makes no output write and increments no write counter. Both counters reset on producer process restart. Source-checked is the last successful direct read timestamp even when validation fails; compare its age rather than treating it as readiness. Acknowledged-valid-until describes this process's last acknowledged output write, not every committed write or a consumer; zero includes process startup and acknowledged withdrawal. Neither timestamp gauge should be rate()d.

Retain positive, wrong-root, repeated key, expiry, missing/deleted source, UID replacement, rollback, output collision/conflict, canceled-before-write, committed-but-lost-ack, restart and API-outage/recovery API/log/metric outputs. Check no output/status churn on idempotent reconciliation. The publisher never exports trust_bundle_ready=1, consumer ACK, mTLS handshake/authorization or Protected from this work. Those existing contracts remain planned until the actual authenticated Cilium/ztunnel consumption, TLS, policy and recovery stories deliver them. No new dashboard is proposed in this producer increment.
