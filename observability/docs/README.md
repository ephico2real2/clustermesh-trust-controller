# CMTC observability

The lab provisions **Operations** and **Workload Security**, consolidating all nine original domains. Their original `01-` through `09-` JSON definitions are preserved unchanged in `observability/dashboards/`; they are reference definitions, not nine additional duplicate live pages. [The root dashboard guide](../../DASHBOARD_GUIDE.md) maps every domain, explains chart meanings and shows measured screenshots.

Operations uses real namespace-intent, node-inventory and controller telemetry. Workload Security incorporates the qualified native two-node mTLS view, plus the original planned TLS performance, trust, transport and violation coverage. The baseline Observe CI does not deploy the isolated SPIRE fixture. Planned panels remain visible and labelled `planned`; missing telemetry is unknown, never a successful zero.

## Generate and validate

```sh
python3 observability/build.py
python3 observability/build.py --check
python3 observability/validate.py
python3 observability/validate.py \
  --prometheus http://127.0.0.1:13000/api/datasources/proxy/uid/cmtc-prom \
  --out artifacts/dashboard-query-evidence.json
```

Import only `dashboards/operations.json` and `dashboards/workload-security.json` for the consolidated layout, mapping `DS_PROMETHEUS` to the intended source. The lab's `monitoring.py` selects those files explicitly. It does not delete or modify the nine originals. Preserve existing monitoring data when reloading provisioning.

The [metric contract](../METRICS.md) covers declared live types and proposed story contracts. The [inventory](../INVENTORY.md) lists actual exporter families, not only the small subset selected for charts. [capabilities.json](../capabilities.json) preserves all 31 original proposed metric names, story IDs and original-file SHA-256 digests. Each delivering story must verify type, labels, event boundary, freshness, absent-source behavior and failure cases before activating a planned panel.

## Integration still to qualify

The ServiceMonitor/PodMonitor and recording/alert rules remain examples. Adjust namespace, selectors and endpoints for the actual Prometheus Operator or OpenShift User Workload Monitoring deployment; validate rule syntax and failure scenarios. Perses/OpenShift rendering, performance SLOs, actual TLS histogram buckets and full protection/rotation/transport signals remain story work. The [source audit](SOURCE_AUDIT.md) preserves the original static findings; its historical imports and gaps must not be mistaken for validation of the current two-page deployment.
