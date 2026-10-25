# Metrics inventory

Source: the page `observer-metrics.prom`

3 metric names in 3 families, 6 series.

| Declared type | Families |
| --- | --- |
| counter | 2 |
| gauge | 1 |

## cmtc_datapath (3)

| Metric | Type | Series | Labels | Kind of data |
| --- | --- | --- | --- | --- |
| `cmtc_datapath_observer_bytes_total` | counter | 2 | direction (1) | a counter: its rate over time; never the raw number |
| `cmtc_datapath_observer_packets_total` | counter | 2 | direction (1) | a counter: its rate over time; never the raw number |
| `cmtc_datapath_observer_ready` | gauge | 2 | direction (1) | a level: a line if it moves, a number or a table if it does not |

