# Experimental node mTLS views

`dashboard.json` and `authenticated-only.json` use the lab's `cmtc-prom` data source. They are separate from the
nine proposed security dashboards and the deployed Observe dashboard. Its
native ztunnel TCP metrics are not CMTC protection or TLS handshake metrics.

The local two-node SPIRE fixture supplies real traffic. Add a Prometheus scrape
job named `cmtc-spire-ztunnel`, path `/stats/prometheus`, with each owned node's
reachable port 15020 and explicit `cluster=cmtc-mtls` and `node` labels. Resolve
addresses from the current lab; do not reuse another machine's node IPs.
Provision the JSON into the existing Grafana CMTC folder, preserving other
files and monitoring data. Poll projected ConfigMap volumes (for example,
`updateIntervalSeconds: 30`) or reload dashboard provisioning in place.

Presentation follows the user's pinned [diagram-kit dashboard skill](https://github.com/ephico2real2/diagram-kit/blob/26b7c19791159929c76a264ea3d5274bef72e9f6/skill/dashboard/SKILL.md):
fixed Tableau outcome/node colours, lower legends, thin shaded lines from zero,
visible definitions and both-theme captures. This is a Grafana fixture; a Perses
or OpenShift rendering has not been qualified.

The [complete metric inventory](METRICS_INVENTORY.md) records 21 names and 51 series
at the measured load window. The selected metrics answer these questions:

| Reader's question | Native source | Presentation |
| --- | --- | --- |
| Are both node metrics reachable? | `up` | Last-value stat, expected 2; not protection |
| How many connections began with or without verified mTLS? | `istio_tcp_connections_opened_total` | Selected-range increases, split by security |
| Which connections were rejected by policy? | `istio_tcp_connections_failed_total{response_flags="DENY"}` | Selected-range increase |
| How are completed attempts classified? | `istio_tcp_connections_closed_total` | One pie with an outcome/value/percentage legend |
| When did traffic flow? | TCP opens and sent/received bytes | Adaptive rate-window lines, source/destination separated |
| Which identities and verdicts were recorded? | Closed counters with principal and verdict labels | Last-value table; lifetime readings, reporters overlap |

Proxy inventory, xDS/cache/admin counters and build facts remain in the inventory;
they do not answer the connection-outcome question or establish authentication.
No TLS handshake or HTTP request metric is synthesized from TCP counters.

Run bounded cross-node Service and Pod-IP load before capture. With the lab
Grafana forwarded on port 13000, the existing `scripts/lab/capture.sh` supports:

```bash
CMTC_CAPTURE_OUT=artifacts/mtls-spike/screenshots \
CMTC_WALK_SPEC=examples/observability/ztunnel-spike/walk.json \
bash scripts/lab/capture.sh
```

Use `authenticated-only-walk.json` for the native authenticated-only trial.
Both browser walks require all twelve panels, in dark and light themes, and permit no `No data` panels
when capturing a recorded load window.
Independently save the PromQL vectors and assert positive traffic rates: a
nonempty graph alone does not establish encrypted or authorized traffic.
Archive request results, node placement, source/image pins, public SVID chains
and packet checks alongside the PNG. Never mount keys or kubeconfigs into the
capture container. [SPIRE qualification](../../../docs/development/SPIRE_SPIKE.md)
records the positive path, the earlier plaintext bypass and the subsequent
native destination-policy trials. Complete fail-closed acceptance remains open.

## Connection counters and outcome percentages

The three headline panels use native destination-reported counter **increases
over the selected time range**, handling proxy restart resets. Prometheus
extrapolates these increases, so they are estimated connection totals:

| Panel | Meaning |
| --- | --- |
| TCP attempts without verified mTLS | TCP opens before authorization, including attempts later rejected. This is not accepted plaintext. |
| Connections rejected by policy — DENY | Failed TCP connections with `response_flags="DENY"`, regardless of authentication state. This is the actual policy rejection counter. |
| mTLS TCP connections started | TCP opens after peer TLS authentication, labeled `mutual_tls`; authorization can still reject them. These are not HTTP requests or TLS handshakes. |

The DENY counter overlaps the attempted-connection counters. Adding these
headline values together would double count rejections.

The pie uses a different, explicit denominator: the selected time range's
**destination-reported completed TCP attempts**, calculated with
`increase(istio_tcp_connections_closed_total[$__range])`. Destination-only
reporting avoids counting both ends of the same connection. Five disjoint
categories exhaust that denominator:

- mTLS with no failure flag.
- Unauthenticated, rejected by policy.
- Authenticated, rejected by policy.
- Unverified, with no failure flag.
- Other failure flags, with either authentication state.

No failure flag does not establish an HTTP success. In-flight connections and
early failures without a completed record are outside the pie. Counter increases
handle resets and use extrapolation; their values are estimates and can be
fractional. Percentages describe TCP outcomes, not HTTP request success rates.

A missing category becomes zero only when the denominator's telemetry exists
and both expected node targets are UP. Missing telemetry stays unavailable.
Zero completed attempts produce no meaningful percentage; do not interpret an
empty pie as protection. Save the exact time range, raw PromQL vectors and the
partition/percentage-sum checks alongside the screenshot. A historical capture
must retain its absolute `from`/`to` values rather than claiming ongoing load.

## Validate locally before CI

The existing CI unit job runs the offline semantic/style checks; no extra workflow
is needed. Query validation records all vectors, notices and elapsed query time.
Use the actual load window, in epoch milliseconds:

```bash
python3 examples/observability/ztunnel-spike/validate.py
python3 examples/observability/ztunnel-spike/validate.py \
  --prometheus http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom \
  --from-ms "$LOAD_FROM_MS" --to-ms "$LOAD_TO_MS" --expect-load \
  --out artifacts/mtls-spike/dashboard-query-evidence.json
```

`--expect-load` requires positive mTLS, rejection and payload signals, so run both
legitimate and unenrolled test traffic. The live check also requires the five pie
categories to equal the closed-counter denominator, percentages to total 100,
and a nonexistent telemetry target to remain empty. The recorded style mutation
test changes one outcome colour and confirms the validator rejects it.
