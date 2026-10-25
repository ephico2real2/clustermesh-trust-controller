# Opt-in datapath metric inventory

This supplements the existing controller/inventory baseline; it does not replace
or regenerate that historical inventory. Source revision is
`5b1bc205fee9c6bc999c7d545e23ac0ff6f29bf2`. Cluster/node identities are retained in
the raw scrape and authoritative Prometheus target ledger. Each exporter covers
one explicitly audited hook per selected node.

## Fence: actual four-node scrape

The diagram-kit inventory below was generated from the four real GET `/metrics`
responses in the second fanout trial. It establishes emitted names/types/series,
not completion of recovery or rendering gates. The run ledger separately records
load deltas, idle checks, exact map identity, local target health and central
remote-write values. Per-node readiness belongs in a latest-state table; packet
and byte counters belong in rates or clearly stated range increases. No request,
TLS, coverage or outcome-share value can be inferred.

# Metrics inventory

Source: the page `fence-metrics.prom`

3 metric names in 3 families, 12 series.

| Declared type | Families |
| --- | --- |
| counter | 2 |
| gauge | 1 |

## cmtc_datapath (3)

| Metric | Type | Series | Labels | Kind of data |
| --- | --- | --- | --- | --- |
| `cmtc_datapath_fence_dropped_bytes_total` | counter | 4 | direction (1) | a counter: its rate over time; never the raw number |
| `cmtc_datapath_fence_dropped_packets_total` | counter | 4 | direction (1) | a counter: its rate over time; never the raw number |
| `cmtc_datapath_fence_quarantine_verified` | gauge | 4 | direction (1) | a level: a line if it moves, a number or a table if it does not |


## Observer

The three observer collectors are implemented in the image. Qualification of their
current scrape/reset/query/render path is pending; no live inventory is substituted
from the family names.
