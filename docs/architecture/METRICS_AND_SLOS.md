# Observability contract and nine dashboards

**Target metric contract with an implemented Observe subset.** See [OBSERVE_LAB.md](../development/OBSERVE_LAB.md) and `internal/telemetry/metrics.go` for current collectors. Protection, workload mTLS, trust lifecycle and dual-encryption signals remain proposed. Existing Cilium/Hubble/SPIRE metrics still require source/scrape verification.

The [observability source audit](../../observability/docs/SOURCE_AUDIT.md) records native Cilium v1.20.4 candidates and gaps across all nine dashboards. The table below is illustrative and incomplete; it does not yet define approved types, labels, freshness or ownership for every expression. Complete CMTC-701 before building exporters or treating absent series as healthy.

| Domain | Representative metrics | Source |
|---|---|---|
| Namespace inventory | `cmtc_namespaces_eligible`, `cmtc_namespaces_enrolled`, `cmtc_namespaces_excluded`, `cmtc_namespace_label_drift_total` | Controller |
| Metadata selection | `cmtc_namespace_selector_matches`, `cmtc_namespace_policy_conflicts_total` | Controller |
| Pods/nodes | `cmtc_pods_protected`, `cmtc_pods_pending`, `cmtc_pod_protection_duration_seconds`, `cmtc_node_agent_ready` | Agent + verified Cilium state |
| Trust | `cmtc_trust_bundle_ready`, `cmtc_trust_bundle_sync_duration_seconds`, `cmtc_ca_rotation_phase`, `cmtc_certificate_expiry_timestamp_seconds` | Hub/agents |
| mTLS | `cmtc_mtls_handshakes_total`, `cmtc_mtls_handshake_duration_seconds`, `cmtc_mtls_identity_validation_failures_total`, `cmtc_remote_identity_resolution_duration_seconds` | Cilium/ztunnel extension |
| Encryption | `cmtc_transport_compatibility_ready`, `cmtc_dual_encryption_probe_success`, `cmtc_mtu_validation_failures_total` | Agent / datapath probes |
| Platform | `cmtc_apiserver_probe_success`, `cmtc_dns_probe_duration_seconds`, `cmtc_platform_compatibility_failures_total`, `cmtc_rollout_aborted_total` | Agent/controller |
| Operations | `cmtc_reconcile_errors_total`, `cmtc_node_config_sync_duration_seconds`, `cmtc_ztunnel_ready` | Controller/agent |

Dashboards: 01 Security Overview; 02 Namespace Enrollment; 03 Pod/Node Enforcement; 04 mTLS Latency; 05 CA Trust/Rotation; 06 Network Encryption; 07 Security Violations; 08 Control Plane Safety; 09 Operator/Agent Health.

Alerts: cluster trust not ready; certificate expiry; rotation blocked; namespace protection gap; failed mTLS; transport incompatibility; API/DNS probe failure; node-agent down. Alert rules in `observability/prometheus/` are starter templates, not production validated.

**SLO candidates, not approved targets:** 99.9% eligible pod protection coverage, 99.9% successful authenticated handshakes for eligible attempts, 99.9% critical dependency probe success, 99% trust propagation under 5 minutes. Baselines, traffic exclusions, budgets and instrumentation must be agreed before adopting.
