# PoC Hubble L7 dashboard by app

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../../../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This imports the user's [demo 37 generator](https://github.com/ephico2real2/cilium-implementation-poc/blob/22fb6e14c0cca8c78af1f072d1e89ebaea6a916b/demos/37-two-gateways/l7-by-app-dashboard.py) byte for byte. `dashboard.json` is its lab-mode output, formatted for review, using the chart from our pinned Cilium source `1bd555f313de3af48529f547e90a336442f5bd91` (its input file is byte-identical to the earlier pin `42f89f83aa`). [source.json](source.json) records both source revisions and the generator, input and output hashes.

The dashboard has UID `hubble-l7-http-by-app` and groups HTTP metrics by `source_app` / `destination_app`. The generator removes the two CPU panels because app labels do not identify a Kubernetes workload. Its historical explanation of remote workload limitations predates upstream Cilium #48563; current main already includes that fix. This example retains app-based grouping and the Gateway-compatible All filters.

Gateway client series can retain a source namespace/workload while `source_app` is empty. Keep source app at All to include that traffic; explicit source-app selection is checked with direct-pod requests. The live regression checks both identities independently.

Use a Hubble-enabled lab with `httpV2` metrics, the app and namespace fields in `labelsContext`, a `cluster` scrape label, and a Prometheus datasource. The [pinned PoC metric values](https://github.com/ephico2real2/cilium-implementation-poc/blob/22fb6e14c0cca8c78af1f072d1e89ebaea6a916b/demos/16-monitoring/values-cilium-metrics.yaml) supply those fields. The fork's Hubble regression deploys this generated dashboard and checks actual Gateway and direct-pod traffic with app names deliberately different from workload names. CMTC's default Observe profile keeps Hubble disabled; this example is exercised by that separate Hubble-enabled qualification.

With a Grafana dashboard sidecar watching `grafana_dashboard=1`, provision it in that Grafana's namespace:

```sh
kubectl -n monitoring create configmap hubble-l7-by-app \
  --from-file=dashboard.json=examples/observability/hubble-l7-by-app/dashboard.json \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n monitoring label configmap hubble-l7-by-app grafana_dashboard=1 --overwrite
```

Regenerate from the source-matched chart and verify the stored example:

```sh
python3 examples/observability/hubble-l7-by-app/l7-by-app-dashboard.py \
  "$CILIUM_SOURCE_DIR/install/kubernetes/cilium/files/hubble/dashboards/hubble-l7-http-metrics-by-workload.json" \
  | python3 -m json.tool --indent 2 > examples/observability/hubble-l7-by-app/dashboard.json
python3 examples/observability/hubble-l7-by-app/check.py \
  "$CILIUM_SOURCE_DIR/install/kubernetes/cilium/files/hubble/dashboards/hubble-l7-http-metrics-by-workload.json"
```

When intentionally changing either source pin, refresh `source.json` together with the generated output and retain new load-driven evidence. The dashboard reports HTTP behavior; it does not establish workload mTLS or node encryption.

The [local ARM64 evidence](https://github.com/ephico2real2/cilium/tree/b13bda7f2e4e30484b8caee2a7f02a180799c157/2026-10-24T0123Z_hubble_l7_by_app_local-macos-arm64) records 151,200/151,200 HTTP 200 responses across three six-minute streams and eleven passing browser cases. All nine app panels had data; app All measured about 400 requests/s, explicit direct source app 20, and source namespace with app All 200. That initial qualification used source `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`; the generator, input chart and generated dashboard hashes are unchanged in the current image source. [Cilium PR #5](https://github.com/ephico2real2/cilium/pull/5) contains the reusable fresh-cluster qualification.
