# CMTC metric meanings and presentation

This contract separates implemented collectors from planned story outputs. A planned type is a design proposal, not a claim that a live exporter exists. The original nine domains and all 31 proposed metric names remain mapped in [capabilities.json](capabilities.json).

The chart follows the value's meaning: gauges are current levels/states, counters become rates or selected-range increases, and latency percentiles come from real histogram buckets. A pie is used only for mutually exclusive categories that exhaust one denominator. No missing security metric is converted to a successful zero.

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

## Planned story contracts

| Proposed metric | Intended type | Meaning | Presentation / owner |
| --- | --- | --- | --- |
| `cmtc_apiserver_probe_success` | gauge | Latest fresh safe API connectivity/TLS probe result. | Mapped latest state/history; not application mTLS or cluster-wide health. Owner: CMTC platform probe. |
| `cmtc_certificate_rotation_failures_total` | counter | Failed certificate rotation attempts or terminal failures with an agreed retry/event boundary. | Failures/s and range increase; retries must not silently multiply terminal failure counts. Owner: CMTC rotation controller. |
| `cmtc_cluster_ready` | gauge | All required verified cluster gates satisfied for the current generation and freshness window. | Mapped status/table; no sum that hides one failed or missing required gate. Owner: CMTC cluster controller. |
| `cmtc_dual_encryption_probe_success` | gauge | Latest fresh controlled probe verifies both workload mTLS and the configured node encryption layer. | Mapped latest probe and state history; absence/staleness is unknown. Owner: CMTC transport probe. |
| `cmtc_issuer_ready` | gauge | Expected issuer can provide a verifiable chain under a defined freshness/issuance check. | Mapped state/history; pod Ready or Issuer object presence is insufficient. Owner: CMTC issuer verifier. |
| `cmtc_mtls_active_connections` | gauge | Currently active verified workload-mTLS connections, counted at one defined endpoint. | Latest value and line if it varies; no rate() or source-plus-destination sum. Owner: Cilium/ztunnel connection lifecycle. |
| `cmtc_mtls_authorization_denials_total` | counter | Destination policy rejections at the authorization boundary. | rate() or range increase, split from identity failures and attempts; avoid double counting. Owner: Cilium/ztunnel authorization. |
| `cmtc_mtls_handshake_duration_seconds` | histogram | Actual workload TLS handshake duration in seconds at the TLS boundary. | p95/p99 from bucket rates grouped by cluster/le and bounded result; no average or TCP-counter substitute. Owner: Cilium/ztunnel TLS boundary. |
| `cmtc_mtls_handshakes_total` | counter | Completed actual TLS handshake observations, labeled by bounded result and one reporting boundary. | rate() by result; selected-range increase for totals; not TCP starts or HTTP requests. Owner: Cilium/ztunnel TLS boundary. |
| `cmtc_mtls_identity_validation_failures_total` | counter | Failed peer certificate/identity validation events at the verifier. | rate() by bounded reason or selected-range increase; not every plaintext attempt. Owner: Cilium/ztunnel peer verifier. |
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

## Acceptance when a story delivers instrumentation

- Confirm the exporter's declared type, units, event boundary, labels and owner on a real scrape; update this contract and inventory.
- Define freshness, restart/reset semantics, a bounded label budget and the behavior for missing sources or no observations.
- Run the real query with success, failure, idle and absent-source cases. A percentile with no samples is unavailable; no eligible traffic has no meaningful success percentage.
- Preserve per-cluster identity and required-gate failures; gauges across overlapping reporters and TCP opens/HTTP requests/TLS handshakes must not be mixed.
- Capture the consolidated section under real relevant load in both themes. Activate and qualify the retained planned panel in its assigned section as the story lands.
- Keep pending/protected/failed pod states mutually exclusive before deriving coverage. Identity/certificate serial/pod-UID detail belongs in logs or bounded drilldowns, not new unbounded CMTC labels.

Reference presentation: [MongoDB chart dashboard rationale](https://github.com/ephico2real2/mongodb-poc/blob/main/chart/mongodb-search-helm/README.md#dashboards) and the pinned [diagram-kit dashboard skill](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/skill/dashboard/SKILL.md).
