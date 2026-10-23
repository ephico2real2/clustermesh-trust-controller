# Observability backlog mapping

Status: Planned. The canonical hierarchy is F08 → EP08 → CMTC-701..706 in [the main backlog](../../docs/agile/BACKLOG.md) and [stories.csv](../../docs/agile/stories.csv). This mapping supersedes the package-local numbering in the input archive, which collided with delivery stories.

| Story | Scope | Acceptance gate |
|---|---|---|
| CMTC-701 | Metric schema and ownership | Types, sources, bounded labels, freshness and missing-data behavior approved for every metric. |
| CMTC-702 | Go exporters | Actual samples match the contract; reset and absent-exporter fixtures pass. |
| CMTC-703 | Cilium/ztunnel telemetry | Native scrapes verified; authentication, policy and transport evidence retain distinct meanings. |
| CMTC-704 | Nine Grafana dashboards | All nine import; p95/p99, cluster drilldown, units and no-data views tested. |
| CMTC-705 | Recording/alert rules | Promtool checks and rule fixtures cover success, denial, zero traffic, missing series and missing clusters. |
| CMTC-706 | Kubernetes/OpenShift monitoring | ServiceMonitor/PodMonitor selectors, ports, RBAC and TLS scrape a supported pinned profile. |

Subtasks and findings: [SOURCE_AUDIT.md](SOURCE_AUDIT.md). Cross-cutting tests and packaging stay CMTC-802..805 in F09 / EP09. No observability story closes from JSON parsing alone.
