# Cursor cross-cluster workload mTLS implementation proposal

Model: Grok 4.7 Extra High. Unaccepted until primary source review and independent local qualification.

Prometheus already aggregates the lab, so I’m checking the live scrape path and the real handshake, connection, and authorization counters before assigning one reporting boundary to each.The verifier patch is unchanged and still unapplied. This addendum does not add an aggregator, a second scrape path, or metric code. Packet and quarantine series stay on the CMTC DaemonSet exporter the primary is wiring.

## Aggregation

Each cluster scrapes its own pods. Discovery is `security.cmtc.io/metrics=true` and the container port named `metrics`, which is already how the controller and node agent are marked in `config/default/workloads.yaml`. Scrape relabeling stamps `cluster`, `component`, and `node`. Those three are the node that exported the sample. Cluster B remote-writes to cluster A node port 30900, and Grafana reads that hub. That is the current lab path, not a new store.

`source_cluster` and `destination_cluster` on ztunnel traffic labels are workload strings from xDS. They stay as workload labels. They do not replace the scrape `cluster` label.

A series missing from the hub does not mean the exporter is down and does not mean a connection was denied. Target health is the local Prometheus target and its `up` series. Remote-write loss is missing data.

Access logs emitted from `ConnectionResult::record_internal` in `src/proxy/metrics.rs` are logs. They are not counters and need their own pipeline.

## One boundary each

Ztunnel already increments the same TCP families at both ends: outbound uses `Reporter::source` (`src/proxy/outbound.rs`) and inbound uses `Reporter::destination` (`src/proxy/inbound.rs`). Summing both reporters counts one proxied connection twice. Every panel below keeps `reporter="destination"` and does not drop that label.

| Question | Single series and labels | Different population, not added in |
|---|---|---|
| TLS handshake failure at the protected workload | `tcp_connections_failed{reporter="destination",response_flags=~"TLS_FAILURE\|IDENTITY_ERROR\|CERT_REVOKED"}` | `H2_HANDSHAKE_FAILURE` is the HTTP/2 setup. `crl_policy_rejections` is a second increment of a revocation and is not added to this query. |
| Completed mTLS connection | `tcp_connections_closed{reporter="destination",connection_security_policy="mutual_tls",response_flags="-"}` | This is one closed connection, not a handshake count and not an HTTP request. |
| Active connection | `tcp_sockets_open{reporter="destination"}` | The source gauge is the client node’s sockets. The two gauges are not added. |
| Destination authorization deny | `tcp_connections_failed{reporter="destination",response_flags="DENY"}` | Source `DENY` is the client node’s early reject. Cilium policy drops are not this flag. |

`tcp_connections_opened` is the proxy accepting a TCP connection. It is not an application SYN attempt, not an HBONE tunnel count, and not an HTTP request. `RequestProtocol::http` is unused, so this process has no HTTP request counter. There is no separate HBONE series in `CommonTrafficLabels`. Until a label distinguishes a pooled HBONE transport from an accepted workload connection, neither is inferred from `tcp_connections_opened`.

No new counter is added for the pinned verifier. A handshake test does not increment these series. Ztunnel is not deployed, so none of these names are lab evidence yet. When a ztunnel DaemonSet is scraped, it joins the existing discovery with `security.cmtc.io/metrics=true` and port name `metrics`. It does not get its own collector.
