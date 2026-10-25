# User instruction: reuse existing Prometheus aggregation

Send this instruction to the same Cursor Grok 4.7 Extra High session after its in-flight revision finishes:

> Yes—and Prometheus already provides the metrics aggregation layer here. Each cluster scrapes its local exporters, and `cmtc-b` remote-writes to the hub in `cmtc-a`, which Grafana queries.
> The DaemonSet telemetry should join that path. We don’t need another CMTC aggregator for counters and gauges.
> We do need to preserve cluster/node labels and avoid double-counting connections reported at both ends; raw flow logs would need a separate pipeline.

Both live Prometheus ConfigMaps and per-cluster/combined query evidence were checked by the primary. The existing collector discovery uses `security.cmtc.io/metrics=true` and the named Pod port `metrics`; scrape relabeling stamps authoritative `cluster`, `component` and `node`. Cluster B currently remote-writes to A's node port30900. This is the existing lab topology, not a new HA/long-term-storage implementation.

Incorporate this into the mTLS proposal: do not introduce a CMTC metric aggregation service, duplicate ingestion, or equate flow logs with counters. Choose and document exactly one reporting boundary for each TLS handshake, active connection and authorization verdict; HTTP requests, TCP attempts, HBONE transport connections and TLS handshakes are different event populations. A central series is not proof that every remote scrape target is healthy; local target state and missing/stale data still matter.

Continue with complete source-backed code/tests and the existing security gates. CMTC packet/quarantine Prometheus and dashboard wiring is being implemented independently by the primary; do not overwrite it. Your response is a proposal only, with no source/runtime mutation or unexecuted success claims.
