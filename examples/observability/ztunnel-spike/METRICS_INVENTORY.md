# Metrics inventory

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../../../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

**Historical inventory** of the retired `cmtc-mtls` fixture. It does not list the metrics of `cmtc-a` or `cmtc-b`.

Source: `{job="cmtc-spire-ztunnel",cluster="cmtc-mtls"}`; query end 2026-10-24T04:50:52Z; measured 2026-10-24

21 metric names in 21 families, 51 series.

| Declared type | Families |
| --- | --- |
| counter | 10 |
| gauge | 6 |
| unknown | 5 |

5 of the 21 names did not change on any series in the last 1h.

## istio_build (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `istio_build` | gauge | 2 | 0 | 1 | component (1), tag (1) | constant, the same on every series: a number or a table row, not a line |

## istio_tcp (6)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `istio_tcp_connections_closed_total` | counter | 3 | 4 | 3 | connection_security_policy (2), destination_app (1), destination_canonical_revision (1), destination_canonical_service (1), destination_cluster (1), destination_principal (1), destination_region (1), destination_service (1), destination_service_name (1), destination_service_namespace (1), destination_version (1), destination_workload (1), destination_workload_namespace (1), destination_zone (1), reporter (2), request_protocol (1), response_flags (3), source_app (1), source_canonical_revision (1), source_canonical_service (1), source_cluster (2), source_principal (2), source_region (1), source_version (1), source_workload (1), source_workload_namespace (2), source_zone (1) | a counter: its rate over time; never the raw number |
| `istio_tcp_connections_failed_total` | counter | 1 | 1 | 1 | connection_security_policy (1), destination_app (1), destination_canonical_revision (1), destination_canonical_service (1), destination_cluster (1), destination_principal (1), destination_region (1), destination_service (1), destination_service_name (1), destination_service_namespace (1), destination_version (1), destination_workload (1), destination_workload_namespace (1), destination_zone (1), reporter (1), request_protocol (1), response_flags (2), source_app (1), source_canonical_revision (1), source_canonical_service (1), source_cluster (1), source_principal (1), source_region (1), source_version (1), source_workload (1), source_workload_namespace (1), source_zone (1) | a counter: its rate over time; never the raw number |
| `istio_tcp_connections_opened_total` | counter | 3 | 3 | 3 | connection_security_policy (2), destination_app (1), destination_canonical_revision (1), destination_canonical_service (1), destination_cluster (1), destination_principal (1), destination_region (1), destination_service (1), destination_service_name (1), destination_service_namespace (1), destination_version (1), destination_workload (1), destination_workload_namespace (1), destination_zone (1), reporter (2), request_protocol (1), response_flags (1), source_app (1), source_canonical_revision (1), source_canonical_service (1), source_cluster (2), source_principal (2), source_region (1), source_version (1), source_workload (1), source_workload_namespace (2), source_zone (1) | a counter: its rate over time; never the raw number |
| `istio_tcp_received_bytes_total` | counter | 3 | 3 | 3 | connection_security_policy (2), destination_app (1), destination_canonical_revision (1), destination_canonical_service (1), destination_cluster (1), destination_principal (1), destination_region (1), destination_service (1), destination_service_name (1), destination_service_namespace (1), destination_version (1), destination_workload (1), destination_workload_namespace (1), destination_zone (1), reporter (2), request_protocol (1), response_flags (1), source_app (1), source_canonical_revision (1), source_canonical_service (1), source_cluster (2), source_principal (2), source_region (1), source_version (1), source_workload (1), source_workload_namespace (2), source_zone (1) | a counter: its rate over time; never the raw number |
| `istio_tcp_sent_bytes_total` | counter | 3 | 3 | 3 | connection_security_policy (2), destination_app (1), destination_canonical_revision (1), destination_canonical_service (1), destination_cluster (1), destination_principal (1), destination_region (1), destination_service (1), destination_service_name (1), destination_service_namespace (1), destination_version (1), destination_workload (1), destination_workload_namespace (1), destination_zone (1), reporter (2), request_protocol (1), response_flags (1), source_app (1), source_canonical_revision (1), source_canonical_service (1), source_cluster (2), source_principal (2), source_region (1), source_version (1), source_workload (1), source_workload_namespace (2), source_zone (1) | a counter: its rate over time; never the raw number |
| `istio_tcp_sockets_open` | gauge | 2 | 1 | 2 | reporter (2) | a level that moves: a line over time; a number for now |

## istio_xds (3)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `istio_xds_connection_terminations_total` | counter | 4 | 0 | 2 | reason (2) | a counter: its rate over time; never the raw number |
| `istio_xds_message_bytes_total` | counter | 4 | 4 | 4 | url (2) | a counter: its rate over time; never the raw number |
| `istio_xds_message_total` | counter | 4 | 4 | 3 | url (2) | a counter: its rate over time; never the raw number |

## process_max (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_max_fds` | gauge | 2 | 0 | 1 |  | constant, the same on every series: a number or a table row, not a line |

## process_open (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_open_fds` | gauge | 2 | 2 | 2 |  | a level that moves: a line over time; a number for now |

## scrape_duration (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_duration_seconds` | unknown | 2 | 2 | 2 |  | a level that moves: a line over time; a number for now |

## scrape_samples (2)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_samples_post_metric_relabeling` | unknown | 2 | 2 | 2 |  | a level that moves: a line over time; a number for now |
| `scrape_samples_scraped` | unknown | 2 | 2 | 2 |  | a level that moves: a line over time; a number for now |

## scrape_series (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_series_added` | unknown | 2 | 1 | 1 |  | a level that moves: a line over time; a number for now |

## up (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `up` | unknown | 2 | 0 | 1 |  | constant, the same on every series: a number or a table row, not a line |

## workload_manager (4)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workload_manager_active_proxy_count` | gauge | 2 | 2 | 2 |  | a level that moves: a line over time; a number for now |
| `workload_manager_pending_proxy_count` | gauge | 2 | 0 | 1 |  | constant, the same on every series: a number or a table row, not a line |
| `workload_manager_proxies_started_total` | counter | 2 | 2 | 2 |  | a counter: its rate over time; never the raw number |
| `workload_manager_proxies_stopped_total` | counter | 2 | 2 | 2 |  | a counter: its rate over time; never the raw number |

Generated with [diagram-kit metrics-inventory](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/diagram_kit/metrics.py). API queries and label discovery are anchored to the recorded load window; declared types come from current Prometheus metadata.
