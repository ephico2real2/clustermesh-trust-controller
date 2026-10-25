# Observability scaffold audit — 2026-10-23

<!-- CMTC_DOC_CONTEXT -->
Research scope: findings apply to the source version named in this document. Read [current delivery status](../../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Historical review of the nine original definitions, which remain unchanged in `observability/dashboards/`. Current live provisioning combines their coverage into two pages; see the [dashboard guide](../../DASHBOARD_GUIDE.md), [metric contracts](../METRICS.md) and [original-to-consolidated mapping](../capabilities.json). The findings below retain their original review baseline.

Static review only. All nine JSON files parsed; each contains five panels (45 panels total). No Grafana import, Prometheus query evaluation or real scrape was performed. No `cmtc_*` collector exists in this repository. Preserve the nine dashboard domains; implementation is CMTC-701..706 under F08 / EP08.

## Findings

| Artifact | Finding | Required acceptance evidence |
|---|---|---|
| Nine dashboards | First metric appears twice on each dashboard as a stat and a time series. This can be intentional, but titles do not distinguish current value/rate or units. | Reviewed panel purpose, units and tested visual import; no claim that 45 panels represent 45 independent signals. |
| `04-mtls-performance.json` | Contains rates, active connections and cache misses, but no p95/p99 latency panels. The separate recording file has a p95 candidate. | Real handshake/identity histograms, agreed buckets and both quantile panels tested with samples. |
| All dashboards and recording rules | Global `sum` drops cluster labels. Only a datasource variable exists. Several health sums show counts rather than an all-required-clusters readiness verdict. | Per-cluster filters/grouping plus explicit fleet rollups; a failing cluster cannot be concealed by healthy peers. |
| `08-control-plane-safety.json` | `rate(cmtc_hostnetwork_pods_total[5m])` is ambiguous: inventory should normally be a gauge, while a counter would measure events. | Approve metric type/meaning before replacing the query; do not invent an exporter to fit it. |
| Pod coverage rule and alert | Arithmetic over different metric names requires compatible label sets; unmatched series disappear. A wholly absent metric/cluster does not satisfy `== 0`. | Rule fixtures for disjoint/missing series, absent exporters, zero eligible workloads and cluster disappearance. Ratios must distinguish unknown/no eligible traffic from real zero. |
| All metrics | Proposed contract varies across documents (`cmtc_cluster_ready`, enforcement failures, platform dependency health, remote cache misses, and several others lack a complete type/label/owner definition). | A single metric contract with owner, source, type, labels, freshness, reset behavior and cardinality budget before instrumentation. |
| ServiceMonitor/PodMonitor | No matching deployments/services/metrics ports or tested RBAC/TLS/selectors exist. | Kubernetes and OpenShift UWM scrape tests against pinned monitoring versions. |
| Prometheus rules | Seven alert definitions and four recording rules are starter expressions. | `promtool check rules` plus rule unit tests with positive/negative/no-data samples. promtool was unavailable during this review. |

## Native candidates

The [pinned Cilium collectors](../../docs/research/SOURCE_AUDIT.md) declare `ztunnel_xds` and `ztunnel_zds` subsystems. Expected fully qualified names are `cilium_ztunnel_xds_enrollment_failures_total{status}`, `cilium_ztunnel_zds_enrollment_total`, `cilium_ztunnel_zds_enrollment_failures_total{status}` and `cilium_ztunnel_zds_connection_active`; final names, enablement and labels must be checked on a live scrape before use. They measure enrollment attempts/errors or the local ZDS connection. They do not establish successful workload handshakes, remote identity binding, application policy, bundle consumption or dual encryption.

Keep `Protected` unknown/pending until fresh enforcement evidence exists. Do not alias enrollment counters or namespace label counts to verified protection. High-cardinality pod/identity/LOB details belong in structured logs/events/Hubble drilldowns. Do not add absent-series production rules until the expected exporter/cluster inventory is defined and tested.

Canonical backlog IDs are in [docs/agile/stories.csv](../../docs/agile/stories.csv); the earlier package-local numbering is superseded.
