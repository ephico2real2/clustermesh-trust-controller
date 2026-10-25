# Observability contract and service targets

The two consolidated dashboards are **Operations** and **Workload Security**. They preserve the nine original domains. The original dashboard definitions remain in the repository.

Read [the metric contract](../../observability/capabilities.json) before adding a collector. Read [the metric inventory](../../observability/METRICS.md) for names, types and ownership. Read [delivery status](../agile/DELIVERY_STATUS.md) for current source and runtime evidence.

## Current signals and planned signals

| Signal | Meaning and limit |
| --- | --- |
| Namespace selection and enrollment | Controller intent and observed labels. These do not prove protection. |
| Node readiness and Pod inventory | Inventory availability. These do not prove traffic capture. |
| Issuer-profile publication | Approved public issuer data and bounded freshness. This does not prove native consumer acceptance. |
| Observer and fence counters | Packets and bytes at the qualified hook. These are not requests or TLS handshakes. |
| Workload mTLS and authorization | Keep planned until the owning implementation supplies real observations. |
| Rotation, recovery and dual encryption | Keep planned until the corresponding failure and recovery tests pass. |

The optional observer and fence passed real scrape and remote-write tests. Their fixtures were removed after qualification. An absent exporter must appear unavailable. Do not replace absent security data with a successful zero.

Prometheus in each cluster scrapes local exporters. Cluster B remote-writes to the hub in cluster A. Grafana queries that hub. Preserve cluster and node labels. Define one reporting owner before aggregating connection counters from both ends.

## Presentation rules

Use the fixed Tableau palette and lower legends. State the counter window and denominator. Keep these concepts separate:

- TCP attempts without verified mTLS. These include attempts rejected later.
- Connections rejected by policy — DENY. This is the rejection counter.
- mTLS TCP connections started. These count authenticated connections.
- HTTP requests and TLS handshakes. These need their own observing boundaries.

A pie chart must partition one stated denominator. Attempts and later rejections overlap; do not add them as exclusive outcomes.

Validate actual queries before capturing Grafana. Generate representative load. Inspect both themes. Keep planned panels visible and clearly labeled.

## Candidate service targets

The following targets are proposals: 99.9% eligible workload protection, 99.9% successful authenticated handshakes, 99.9% critical dependency availability, and 99% trust propagation within five minutes.

These targets require agreed exclusions, measurement windows and error budgets. They are not approved production SLOs. Alert templates in `observability/prometheus` also require real signal and failure qualification.
