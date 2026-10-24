# Experimental cross-node mTLS view

`dashboard.json` uses the lab's `cmtc-prom` data source. It is separate from the
nine proposed security dashboards and the deployed Observe dashboard. Its
native ztunnel TCP metrics are not CMTC protection or TLS handshake metrics.

The local two-node SPIRE fixture supplies real traffic. Add a Prometheus scrape
job named `cmtc-spire-ztunnel`, path `/stats/prometheus`, with each owned node's
reachable port 15020 and explicit `cluster=cmtc-mtls` and `node` labels. Resolve
addresses from the current lab; do not reuse another machine's node IPs.
Provision the JSON into the existing Grafana CMTC folder, preserving other
files and monitoring data. Poll projected ConfigMap volumes (for example,
`updateIntervalSeconds: 30`) or reload dashboard provisioning in place.

Run bounded cross-node Service and Pod-IP load before capture. With the lab
Grafana forwarded on port 13000, the existing `scripts/lab/capture.sh` supports:

```bash
CMTC_CAPTURE_OUT=artifacts/mtls-spike/screenshots \
CMTC_WALK_SPEC=examples/observability/ztunnel-spike/walk.json \
bash scripts/lab/capture.sh
```

The browser walk requires all nine panels and permits no `No data` panels.
Independently save the PromQL vectors and assert positive traffic rates: a
nonempty graph alone does not establish encrypted or authorized traffic.
Archive request results, node placement, source/image pins, public SVID chains
and packet checks alongside the PNG. Never mount keys or kubeconfigs into the
capture container. [SPIRE qualification](../../../docs/development/SPIRE_SPIKE.md)
records the positive path and the still-open plaintext-bypass negative case.
