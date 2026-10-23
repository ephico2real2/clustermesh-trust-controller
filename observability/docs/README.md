# CMTC Observability Starter Package

Includes nine Grafana JSON dashboards, recording rules, alerts, ServiceMonitor and PodMonitor examples, and Agile stories.

**Design artifacts, not a functioning CMTC deployment.** All `cmtc_*` metrics are proposed and require instrumentation. Dashboard panels will show No data until exporters are implemented. Native Cilium/ztunnel metrics must be mapped after pinning a Cilium version.

The [source audit](SOURCE_AUDIT.md) now reviews all nine files against the Cilium v1.20.4 research baseline. Imports, native scrapes, PromQL semantics, latency panels, cluster grouping and missing-data behavior still require implementation and tests. Canonical delivery IDs are CMTC-701..706 in [the main backlog](../../docs/agile/BACKLOG.md).

## Installation sequence
1. Deploy CMTC metrics endpoints (future implementation).
2. Enable Prometheus Operator or OpenShift User Workload Monitoring and verify monitoring selectors.
3. Apply `kubernetes/monitoring.yaml` after adjusting namespace, labels and metrics port.
4. Convert `prometheus/*.yaml` groups to `PrometheusRule.spec.groups` or load as Prometheus rule files.
5. Import `dashboards/*.json` into Grafana and map `DS_PROMETHEUS` to the Prometheus datasource.
6. Validate rules with `promtool check rules prometheus/*.yaml`, then inject failure scenarios.

## Metric design notes
- Namespace label presence is enrollment intent, not enforcement proof.
- Handshake, identity, bypass and transport measurements require Cilium/ztunnel or datapath instrumentation.
- Never use pod UID, SPIFFE URI, arbitrary namespace labels or certificate serials as high-cardinality Prometheus labels.
- Cluster-level aggregations must use a unique `cluster` label from scrape relabeling or instrumentation; multi-cluster aggregation requires consistent external labels.
- Missing metrics are unknown, not zero. Add absent-series alerts once exporters are deployed.
- Do not probe sensitive API/webhook operations merely to create monitoring traffic.
- Current files are starter dashboards and example rules; performance SLOs and exact histogram buckets are pending design review.
