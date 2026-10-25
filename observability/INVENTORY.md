# Metrics inventory

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Source: CMTC collectors and their runtime; measured October 24, 2026 America/Chicago; {job="cmtc",component=~"cmtc-controller|cmtc-node-agent"}

207 metric names in 183 families, 1689 series.

| Declared type | Families |
| --- | --- |
| counter | 93 |
| gauge | 73 |
| histogram | 11 |
| summary | 1 |
| unknown | 5 |

107 of the 207 names did not change on any series in the last 1h.

## certwatcher_read (2)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `certwatcher_read_certificate_errors_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `certwatcher_read_certificate_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |

## cmtc_enforcement (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_enforcement_available` | gauge | 2 | 0 | 1 | component (1), exported_cluster (2) | constant, the same on every series: a number or a table row, not a line |

## cmtc_namespace (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_namespace_decisions` | gauge | 8 | 0 | 4 | component (1), decision (4), exported_cluster (2) | constant, differing by series: a table or sorted bars, not a line |

## cmtc_namespaces (3)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_namespaces_eligible` | gauge | 2 | 0 | 1 | component (1), exported_cluster (2) | constant, the same on every series: a number or a table row, not a line |
| `cmtc_namespaces_enrolled` | gauge | 2 | 0 | 1 | component (1), exported_cluster (2) | constant, the same on every series: a number or a table row, not a line |
| `cmtc_namespaces_selected` | gauge | 2 | 0 | 1 | component (1), exported_cluster (2) | constant, the same on every series: a number or a table row, not a line |

## cmtc_node (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_node_agent_ready` | gauge | 4 | 0 | 1 | component (1), exported_cluster (2), exported_node (4) | constant, the same on every series: a number or a table row, not a line |

## cmtc_pods (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_pods_observed` | gauge | 8 | 0 | 5 | component (1), exported_cluster (2), exported_node (4), network (2) | constant, differing by series: a table or sorted bars, not a line |

## cmtc_policy (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `cmtc_policy_evaluations_total` | counter | 2 | 2 | 2 | component (1), exported_cluster (2) | a counter: its rate over time; never the raw number |

## controller_runtime (12)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `controller_runtime_active_workers` | gauge | 2 | 0 | 1 | component (1), controller (1) | constant, the same on every series: a number or a table row, not a line |
| `controller_runtime_conversion_webhook_panics_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `controller_runtime_max_concurrent_reconciles` | gauge | 2 | 0 | 1 | component (1), controller (1) | constant, the same on every series: a number or a table row, not a line |
| `controller_runtime_reconcile_errors_total` | counter | 2 | 0 | 1 | component (1), controller (1) | a counter: its rate over time; never the raw number |
| `controller_runtime_reconcile_panics_total` | counter | 2 | 0 | 1 | component (1), controller (1) | a counter: its rate over time; never the raw number |
| `controller_runtime_reconcile_time_seconds_bucket` | histogram | 82 | 82 | 5 | component (1), controller (1), le (41) | a distribution: a percentile from its buckets, across instances |
| `controller_runtime_reconcile_time_seconds_count` | histogram | 2 | 2 | 2 | component (1), controller (1) | a distribution: a percentile from its buckets, across instances |
| `controller_runtime_reconcile_time_seconds_sum` | histogram | 2 | 2 | 2 | component (1), controller (1) | a distribution: a percentile from its buckets, across instances |
| `controller_runtime_reconcile_timeouts_total` | counter | 2 | 0 | 1 | component (1), controller (1) | a counter: its rate over time; never the raw number |
| `controller_runtime_reconcile_total` | counter | 8 | 2 | 4 | component (1), controller (1), result (4) | a counter: its rate over time; never the raw number |
| `controller_runtime_terminal_reconcile_errors_total` | counter | 2 | 0 | 1 | component (1), controller (1) | a counter: its rate over time; never the raw number |
| `controller_runtime_webhook_panics_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |

## go_cgo (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_cgo_go_to_c_calls_calls_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |

## go_cpu (11)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_cpu_classes_gc_mark_assist_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_gc_mark_dedicated_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_gc_mark_idle_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_gc_pause_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_gc_total_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_idle_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_scavenge_assist_cpu_seconds_total` | counter | 6 | 0 | 5 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_scavenge_background_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_scavenge_total_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_total_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_cpu_classes_user_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |

## go_gc (35)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_gc_cleanups_executed_cleanups_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_cleanups_queued_cleanups_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_cycles_automatic_gc_cycles_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_cycles_forced_gc_cycles_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_cycles_total_gc_cycles_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_duration_seconds` | summary | 30 | 18 | 30 | component (2), quantile (5) | a summary: an average from _sum over _count; its own quantiles do not combine across instances |
| `go_gc_duration_seconds_count` | summary | 6 | 6 | 6 | component (2) | a summary: an average from _sum over _count; its own quantiles do not combine across instances |
| `go_gc_duration_seconds_sum` | summary | 6 | 6 | 6 | component (2) | a summary: an average from _sum over _count; its own quantiles do not combine across instances |
| `go_gc_finalizers_executed_finalizers_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_finalizers_queued_finalizers_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_gogc_percent` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_gc_gomemlimit_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_gc_heap_allocs_by_size_bytes_bucket` | histogram | 72 | 72 | 72 | component (2), le (12) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_allocs_by_size_bytes_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_allocs_by_size_bytes_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_allocs_bytes_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_heap_allocs_objects_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_heap_frees_by_size_bytes_bucket` | histogram | 72 | 72 | 72 | component (2), le (12) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_frees_by_size_bytes_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_frees_by_size_bytes_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_heap_frees_bytes_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_heap_frees_objects_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_heap_goal_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_heap_live_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_heap_objects_objects` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_heap_tiny_allocs_objects_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_gc_limiter_last_enabled_gc_cycle` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_gc_pauses_seconds_bucket` | histogram | 48 | 36 | 24 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_gc_pauses_seconds_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_pauses_seconds_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_gc_scan_globals_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_gc_scan_heap_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_scan_stack_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_scan_total_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_gc_stack_starting_size_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |

## go_godebug (48)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_godebug_non_default_behavior_allowmultiplevcs_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_asynctimerchan_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_containermaxprocs_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_cryptocustomrand_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_embedfollowsymlinks_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_execerrdot_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_fips140ems_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_gocachehash_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_gocachetest_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_gocacheverify_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_gotestjsonbuildtext_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_gotypesalias_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_htmlmetacontenturlescape_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_http2client_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_http2server_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_httpcookiemaxnum_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_httplaxcontentlength_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_httpmuxgo121_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_httpservecontentkeepheaders_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_httpservecontentmaxranges_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_installgoroot_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_multipartmaxheaders_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_multipartmaxparts_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_multipathtcp_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_netedns0_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_panicnil_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_randautoseed_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_randseednop_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_rsa1024min_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tarinsecurepath_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tls10server_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tls3des_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tlsmaxrsasize_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tlsrsakex_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tlssha1_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_tlsunsafeekm_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_updatemaxprocs_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_urlmaxqueryparams_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_urlstrictcolons_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_winreadlinkvolume_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_winsymlink_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509keypairleaf_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509negativeserial_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509rsacrt_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509sha256skid_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509usefallbackroots_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_x509usepolicies_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |
| `go_godebug_non_default_behavior_zipinsecurepath_events_total` | counter | 6 | 0 | 1 | component (2) | a counter: its rate over time; never the raw number |

## go_goroutines (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_goroutines` | gauge | 6 | 6 | 3 | component (2) | a level that moves: a line over time; a number for now |

## go_info (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_info` | gauge | 6 | 0 | 1 | component (2), version (1) | facts as labels: a table |

## go_memory (14)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_memory_classes_heap_free_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_heap_objects_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_heap_released_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_heap_stacks_bytes` | gauge | 6 | 6 | 4 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_heap_unused_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_metadata_mcache_free_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_memory_classes_metadata_mcache_inuse_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_memory_classes_metadata_mspan_free_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_metadata_mspan_inuse_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_metadata_other_bytes` | gauge | 6 | 1 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_os_stacks_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_memory_classes_other_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_profiling_buckets_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memory_classes_total_bytes` | gauge | 6 | 0 | 5 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## go_memstats (22)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_memstats_alloc_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_alloc_bytes_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_memstats_buck_hash_sys_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_frees_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_memstats_gc_sys_bytes` | gauge | 6 | 1 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_alloc_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_idle_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_inuse_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_objects` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_released_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_heap_sys_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_last_gc_time_seconds` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_mallocs_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_memstats_mcache_inuse_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_memstats_mcache_sys_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_memstats_mspan_inuse_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_mspan_sys_bytes` | gauge | 6 | 0 | 3 | component (2) | constant, differing by series: a table or sorted bars, not a line |
| `go_memstats_next_gc_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_other_sys_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_stack_inuse_bytes` | gauge | 6 | 6 | 4 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_stack_sys_bytes` | gauge | 6 | 6 | 4 | component (2) | a level that moves: a line over time; a number for now |
| `go_memstats_sys_bytes` | gauge | 6 | 0 | 5 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## go_sched (23)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_sched_gomaxprocs_threads` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |
| `go_sched_goroutines_created_goroutines_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `go_sched_goroutines_goroutines` | gauge | 6 | 6 | 2 | component (2) | a level that moves: a line over time; a number for now |
| `go_sched_goroutines_not_in_go_goroutines` | gauge | 6 | 2 | 2 | component (2) | a level that moves: a line over time; a number for now |
| `go_sched_goroutines_runnable_goroutines` | gauge | 6 | 6 | 4 | component (2) | a level that moves: a line over time; a number for now |
| `go_sched_goroutines_running_goroutines` | gauge | 6 | 6 | 3 | component (2) | a level that moves: a line over time; a number for now |
| `go_sched_goroutines_waiting_goroutines` | gauge | 6 | 6 | 4 | component (2) | a level that moves: a line over time; a number for now |
| `go_sched_latencies_seconds_bucket` | histogram | 48 | 48 | 36 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_sched_latencies_seconds_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_latencies_seconds_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_gc_seconds_bucket` | histogram | 48 | 38 | 29 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_gc_seconds_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_gc_seconds_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_other_seconds_bucket` | histogram | 48 | 0 | 1 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_other_seconds_count` | histogram | 6 | 0 | 1 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_stopping_other_seconds_sum` | histogram | 6 | 0 | 1 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_gc_seconds_bucket` | histogram | 48 | 36 | 24 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_gc_seconds_count` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_gc_seconds_sum` | histogram | 6 | 6 | 6 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_other_seconds_bucket` | histogram | 48 | 0 | 1 | component (2), le (8) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_other_seconds_count` | histogram | 6 | 0 | 1 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_pauses_total_other_seconds_sum` | histogram | 6 | 0 | 1 | component (2) | a distribution: a percentile from its buckets, across instances |
| `go_sched_threads_total_threads` | gauge | 6 | 0 | 2 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## go_sync (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_sync_mutex_wait_total_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |

## go_threads (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `go_threads` | gauge | 6 | 0 | 2 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## leader_election (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `leader_election_master_status` | gauge | 2 | 0 | 1 | component (1), name (1) | constant, the same on every series: a number or a table row, not a line |

## process_cpu (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_cpu_seconds_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |

## process_max (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_max_fds` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |

## process_network (2)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_network_receive_bytes_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |
| `process_network_transmit_bytes_total` | counter | 6 | 6 | 6 | component (2) | a counter: its rate over time; never the raw number |

## process_open (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_open_fds` | gauge | 6 | 6 | 1 | component (2) | a level that moves: a line over time; a number for now |

## process_resident (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_resident_memory_bytes` | gauge | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |

## process_start (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_start_time_seconds` | gauge | 6 | 0 | 4 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## process_virtual (2)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `process_virtual_memory_bytes` | gauge | 6 | 0 | 2 | component (2) | constant, differing by series: a table or sorted bars, not a line |
| `process_virtual_memory_max_bytes` | gauge | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |

## rest_client (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `rest_client_requests_total` | counter | 16 | 10 | 11 | code (4), component (2), host (2), method (4) | a counter: its rate over time; never the raw number |

## scrape_duration (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_duration_seconds` | unknown | 6 | 6 | 6 | component (2) | a level that moves: a line over time; a number for now |

## scrape_samples (2)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_samples_post_metric_relabeling` | unknown | 6 | 0 | 3 | component (2) | constant, differing by series: a table or sorted bars, not a line |
| `scrape_samples_scraped` | unknown | 6 | 0 | 3 | component (2) | constant, differing by series: a table or sorted bars, not a line |

## scrape_series (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `scrape_series_added` | unknown | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |

## up (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `up` | unknown | 6 | 0 | 1 | component (2) | constant, the same on every series: a number or a table row, not a line |

## workqueue_adds (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_adds_total` | counter | 2 | 2 | 2 | component (1), controller (1), name (1) | a counter: its rate over time; never the raw number |

## workqueue_depth (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_depth` | gauge | 3 | 0 | 1 | component (1), controller (1), name (1), priority (2) | constant, the same on every series: a number or a table row, not a line |

## workqueue_longest (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_longest_running_processor_seconds` | gauge | 2 | 0 | 1 | component (1), controller (1), name (1) | constant, the same on every series: a number or a table row, not a line |

## workqueue_queue (3)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_queue_duration_seconds_bucket` | histogram | 26 | 20 | 10 | component (1), controller (1), le (13), name (1) | a distribution: a percentile from its buckets, across instances |
| `workqueue_queue_duration_seconds_count` | histogram | 2 | 2 | 2 | component (1), controller (1), name (1) | a distribution: a percentile from its buckets, across instances |
| `workqueue_queue_duration_seconds_sum` | histogram | 2 | 2 | 2 | component (1), controller (1), name (1) | a distribution: a percentile from its buckets, across instances |

## workqueue_retries (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_retries_total` | counter | 2 | 2 | 2 | component (1), controller (1), name (1) | a counter: its rate over time; never the raw number |

## workqueue_unfinished (1)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_unfinished_work_seconds` | gauge | 2 | 0 | 1 | component (1), controller (1), name (1) | constant, the same on every series: a number or a table row, not a line |

## workqueue_work (3)

| Metric | Type | Series | Changed | Distinct values | Labels | Kind of data |
| --- | --- | --- | --- | --- | --- | --- |
| `workqueue_work_duration_seconds_bucket` | histogram | 26 | 14 | 6 | component (1), controller (1), le (13), name (1) | a distribution: a percentile from its buckets, across instances |
| `workqueue_work_duration_seconds_count` | histogram | 2 | 2 | 2 | component (1), controller (1), name (1) | a distribution: a percentile from its buckets, across instances |
| `workqueue_work_duration_seconds_sum` | histogram | 2 | 2 | 2 | component (1), controller (1), name (1) | a distribution: a percentile from its buckets, across instances |


Generated with diagram-kit metrics-inventory at 26b7c19791159929c76a264ea3d5274bef72e9f6. See [METRICS.md](METRICS.md) for the selected signals and the planned story contracts.
