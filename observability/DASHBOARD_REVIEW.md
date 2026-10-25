# CMTC dashboard review

The original six-panel Observe page showed inventory and intent. The nine security prototypes contained many unimplemented metrics. Consolidation made that missing telemetry dominate both pages. The new layout puts actual data and collection coverage first. It preserves all nine historical domains and their source hashes.

Operations shows controller/node inventory, namespace decisions, errors and latency. Workload Security shows ztunnel scrape coverage and the current public issuer-profile producer. Optional packet diagnostics, native mTLS diagnostics and future contracts remain expandable. A zero target count reads **None reporting**, not healthy or zero traffic. Planned and hidden capabilities remain BLOCKED in capture evidence. No dashboard establishes Protected.

Counters use rates or explicit selected-range increases. Gauges use their latest selected-range value. Real handshake latency requires histogram buckets at the TLS owner. TCP attempts, rejections, authenticated connections, TLS handshakes and HTTP requests remain separate. The outcome pie partitions destination-reported completed TCP attempts once. Missing sources and partial scrape coverage must be checked before interpreting totals as cluster-wide.

Cluster identity is fixed blue/red. Outcome charts use fixed Tableau result colours and dashed cmtc-b lines. Both themes were inspected. Namespace All includes empty labels. Stable dashboard UIDs and cross-links remain unchanged. No historical dashboard definition was deleted.

Source ownership is explicit in metrics.json. Ztunnel TCP collectors are implemented in the proxy; actual TLS handshake collectors remain planned until their code, tests and live scrape are qualified. The issuer profile measures publication and read freshness, not certificate consumption or encryption. Prometheus remains the aggregator, including cmtc-b remote-write to cmtc-a.

Local qualification includes reproducible JSON, typed/owner-scoped query validation, all nine domains, 19 dashboard tests, live queries for both clusters and each cluster, a refreshed full inventory, a real six-minute eight-stream load and both-theme captures. Promtool passes 13 groups, 45 expression checks and eight alert checks. The first palette render found invalid regex overrides; the final render verifies fixed colours and dashed lines. See [the evidence](../docs/evidence/dashboard-refactor/README.md).

## Panel decisions

### CMTC | Operations

| ID | Panel | Presentation decision |
| ---: | --- | --- |
| 1 | CMTC operations · observed intent and inventory | Explain scope and limits beside the readings. |
| 3 | Controllers reporting | Show by default; use actual inventory, coverage or public-producer data. |
| 4 | Node inventories ready | Show by default; use actual inventory, coverage or public-producer data. |
| 5 | Namespaces selected · intent | Show by default; use actual inventory, coverage or public-producer data. |
| 6 | Enforcement verification | Show by default; use actual inventory, coverage or public-producer data. |
| 8 | Enrollment labels observed | Show by default; use actual inventory, coverage or public-producer data. |
| 9 | Non-platform namespaces observed | Show by default; use actual inventory, coverage or public-producer data. |
| 10 | Namespace decisions · latest share | Show by default; use actual inventory, coverage or public-producer data. |
| 11 | Namespace decisions by cluster | Show by default; use actual inventory, coverage or public-producer data. |
| 12 | Read the namespace categories | Explain scope and limits beside the readings. |
| 14 | Inventory/controller targets reachable | Show by default; use actual inventory, coverage or public-producer data. |
| 15 | Controller reconcile errors · selected range | Show by default; use actual inventory, coverage or public-producer data. |
| 16 | Policy evaluations/s · by cluster | Show by default; use actual inventory, coverage or public-producer data. |
| 17 | Controller reconcile p95 · seconds | Show by default; use actual inventory, coverage or public-producer data. |
| 18 | Pod inventory by node | Show by default; use actual inventory, coverage or public-producer data. |
| 19 | Inventory/controller targets · current state | Show by default; use actual inventory, coverage or public-producer data. |
| 20 | Inventory and controller telemetry boundaries | Explain scope and limits beside the readings. |
| 22 | Implementation status · documented scope, not live health | Explain scope and limits beside the readings. |
| 31 | Packet counters and quarantine scope | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 32 | Audited quarantine · latest by node | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 33 | Packets rejected by audited quarantine/s | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 34 | Quarantine rejected packets · selected range | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 35 | skb bytes rejected by quarantine/s | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 36 | Fence metrics targets · latest reachability | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 41 | Read observation separately from quarantine | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 42 | Audited observer · latest by node | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 43 | Packets observed before Cilium verdict/s | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 44 | skb bytes observed before Cilium verdict/s | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 45 | Observer metrics targets · latest reachability | Keep as optional audited-veth diagnostics; packets are not TLS. |
| 101 | Verified cluster gates · planned | Preserve in its planned section; require the owning collector and actual data. |
| 102 | Pods protected · planned | Preserve in its planned section; require the owning collector and actual data. |
| 103 | Pods awaiting enforcement · planned | Preserve in its planned section; require the owning collector and actual data. |
| 104 | Pods enforcement failed · planned | Preserve in its planned section; require the owning collector and actual data. |
| 106 | Platform dependency health · planned | Preserve in its planned section; require the owning collector and actual data. |
| 107 | API probe result · planned | Preserve in its planned section; require the owning collector and actual data. |
| 108 | Rollouts aborted/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 110 | Enrollment label drift/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 111 | Node configuration drift/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 112 | Proxy configuration ready · planned | Preserve in its planned section; require the owning collector and actual data. |

### CMTC | Workload Security

| ID | Panel | Presentation decision |
| ---: | --- | --- |
| 1 | CMTC workload security · node ztunnel mTLS, authorization and trust | Explain scope and limits beside the readings. |
| 3 | ztunnel telemetry coverage · latest by cluster | Show by default; use actual inventory, coverage or public-producer data. |
| 24 | Issuer-profile producer · latest by cluster | Show by default; use actual inventory, coverage or public-producer data. |
| 25 | Issuer-profile validation attempts/s · by result | Show by default; use actual inventory, coverage or public-producer data. |
| 26 | Issuer-profile publication writes/s · by state and result | Show by default; use actual inventory, coverage or public-producer data. |
| 27 | Read issuer-profile signals | Explain scope and limits beside the readings. |
| 4 | Workloads managed by ztunnel · latest by node | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 5 | xDS stream terminations/s · by cluster | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 7 | mTLS TCP connections opened · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 8 | TCP opens without verified mTLS · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 9 | Connections rejected by policy (DENY) · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 10 | Completed TCP attempts · share by outcome | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 11 | Completed TCP attempts by cluster and outcome · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 12 | Read connection counts and shares | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 14 | mTLS TCP opens/s · destination cluster ← source trust domain | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 15 | mTLS payload bytes/s · source cluster → destination trust domain | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 16 | Cluster-pair mTLS connections · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 18 | TCP close verdicts and verified peer identities · selected range | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 21 | Connections rejected by policy/s · ztunnel DENY | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 22 | Read violation signals | Keep in native diagnostics; require exact-node ztunnel data and real traffic. |
| 101 | TLS handshakes/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 102 | Active mTLS connections · planned | Preserve in its planned section; require the owning collector and actual data. |
| 103 | Peer identity validation failures/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 104 | Remote identity cache misses/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 105 | TLS handshake p95 · planned | Preserve in its planned section; require the owning collector and actual data. |
| 107 | Trust bundle consumed · planned | Preserve in its planned section; require the owning collector and actual data. |
| 108 | SPIRE API acknowledged · planned | Preserve in its planned section; require the owning collector and actual data. |
| 109 | Issuer chain verified · planned | Preserve in its planned section; require the owning collector and actual data. |
| 110 | Certificate rotation failures/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 112 | Transport profile verified · planned | Preserve in its planned section; require the owning collector and actual data. |
| 113 | Dual encryption probe result · planned | Preserve in its planned section; require the owning collector and actual data. |
| 114 | Transport encryption failures/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 115 | MTU validation failures/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 117 | Plaintext bypass incidents/s · planned | Preserve in its planned section; require the owning collector and actual data. |
| 118 | Namespace policy conflicts/s · planned | Preserve in its planned section; require the owning collector and actual data. |
