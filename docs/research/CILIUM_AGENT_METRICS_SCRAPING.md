# Cilium agent metrics scraping in the local ClusterMesh lab

<!-- CMTC_DOC_CONTEXT -->
Research scope: findings apply to the source version named in this document. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

This note records the fifth work item, [issue #17](https://github.com/ephico2real2/clustermesh-trust-controller/issues/17), and the submitted ServiceMonitor proposal. It connects the remote xDS mapping in [issue #16](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16) to the existing metric contract in [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15). The related xDS test probe is [issue #14](https://github.com/ephico2real2/clustermesh-trust-controller/issues/14).

This is a qualification plan, not evidence that a custom CMTC collector currently exists or that dashboards are receiving its series.

## Corrections to the submitted manifest

The proposed `apiVersion: ://coreos.com` is malformed. The Prometheus Operator API is `monitoring.coreos.com/v1`. A ServiceMonitor's selector matches **Service labels**, and `endpoints[].port` names a port on the selected Service. It is not a direct Pod selector or a metrics exporter.

The inspected Cilium chart at source pin `f142e58d06a458b72cf7ea27999c093ca87c9c2b` already provides an agent ServiceMonitor, gated by `prometheus.enabled` and `prometheus.serviceMonitor.enabled`. The agent Service exposes a named `metrics` port; the default agent metrics port is 9962. First render and inspect the exact chart values and resources. Use the chart-native resource if it satisfies the installed Prometheus selectors; only add another monitor if local evidence demonstrates a gap.

The suggested `release: cmtc-prometheus` metadata works only when it matches the live Prometheus `serviceMonitorSelector`. Prometheus `serviceMonitorSelector` and `serviceMonitorNamespaceSelector` govern which ServiceMonitor objects Prometheus loads; the ServiceMonitor's `namespaceSelector` governs where it looks for Services. These selectors are separate.

The proposed metric relabel regex `cilium_.*|cmtc_.*` drops Go runtime, process, and any other metric families. Do not apply that filter without checking the actual series needed by the lab. Creating a ServiceMonitor does not register a collector, make a planned metric live, or establish a security event.

## Optional manifest shape

The following is a **shape for review only**, not a command to apply. Prefer Cilium's rendered chart-native monitor when it meets the live selectors. Replace every selector/label only after inspecting the actual Service and Prometheus objects; omit metric relabeling unless the retained-series set has been validated.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cilium-agent-cmtc-monitor
  namespace: kube-system
  labels:
    # Must match the installed Prometheus serviceMonitorSelector.
    # Do not assume this release label is correct.
    release: <verified-prometheus-selector-label>
spec:
  selector:
    # Must match labels on the Cilium agent Service, not only its Pods.
    matchLabels:
      app.kubernetes.io/name: cilium-agent
  namespaceSelector:
    matchNames:
      - kube-system
  endpoints:
    # Must match a named port on the selected Service.
    - port: metrics
      path: /metrics
      interval: 10s
      scrapeTimeout: 8s
```

The actual chart template and rendered Service are authoritative. A hard-coded `k8s-app: cilium` selector may happen to match a service today, but verify the target Service labels and the pinned chart before using it.

## Local validation procedure

1. Resolve the current contexts for the owned `cmtc-a` and `cmtc-b` clusters from kubeconfig. Do not use placeholder context names from the pasted example.
2. In each cluster, verify the Prometheus Operator and ServiceMonitor CRD, then inspect the Prometheus selectors and the Cilium Helm values.
3. Render the pinned Cilium chart. Check the actual `cilium-agent` Service labels, named `metrics` port/target port, chart-native ServiceMonitor labels, endpoint and namespace.
4. Apply a separate ServiceMonitor only after showing that the built-in one does not satisfy the actual selectors. Avoid duplicate jobs.
5. Confirm all expected node targets appear under the correct ServiceMonitor and report UP. Then query representative Cilium metrics and check retained Go/process series if they are part of the current scrape contract.
6. Query a CMTC metric only when the owning collector is registered in the tested agent image. Deliberately exercise the event that metric represents, and compare its value to logs/xDS outcomes. A missing series is unavailable; it is not zero-valued success.
7. Run the existing validator with the actual local Prometheus URL and required evidence output:

   ```bash
   python3 observability/validate.py \
     --prometheus http://127.0.0.1:<actual-port> \
     --out artifacts/dashboard-query-evidence.json
   ```

8. Record raw target/query output, cluster context, chart/source pin, exact image ID, and selected tests. Capture Grafana screenshots only after representative load and matching real query evidence.

For the two dashboards, preserve the distinction between test-only mock translation, xDS send/ACK, verified workload identity, actual policy denial, and application traffic. A non-zero mock counter must never make a production security panel appear live. See [REMOTE_XDS_OBSERVABILITY.md](REMOTE_XDS_OBSERVABILITY.md).

## References

- [Cilium metrics documentation](https://docs.cilium.io/en/stable/observability/metrics/)
- [Prometheus Operator ServiceMonitor selection and troubleshooting](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/platform/troubleshooting.md)
- [Issue #16: remote workload xDS mapping](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16)
- [Issue #18: remote xDS transformer tests](https://github.com/ephico2real2/clustermesh-trust-controller/issues/18)
