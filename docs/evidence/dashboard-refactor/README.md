# Local dashboard qualification

The compact Operations and Workload Security views show actual inventory and public issuer-profile data. The default views have no empty data panels in this run. Ztunnel is disabled. These results do not prove workload mTLS.

The dashboards retain all nine historical domains. Native proxy diagnostics, optional packet diagnostics and planned contracts remain expandable. Capture evidence retains their BLOCKED state even when the sections are collapsed. A missing proxy target reads **None reporting**.

## Load and queries

The six-minute run `compact-261025100251` used eight fixed load processes across `cmtc-a` and `cmtc-b`. All **28,800 requests returned HTTP 200**. The mesh streams used ports 80, 8080 and 31337. The shop streams used the imported example applications.

- [Measured load results](load-results.json) record each stream's requests, rate and duration.
- [Frozen collection](frozen-load-collection.json) binds the final logs to the original processes.
- [Capture timeline](timeline-results.json) records three rounds. Each round checked those same processes before, during and after capture.
- [Live query evidence](query-evidence.json) contains actual query results for both clusters and each selected cluster.
- [Metric inventory](live-inventory.md) records 205 names, 181 families and 1,658 series.

The first render exposed invalid Grafana regex overrides. [The diagnostic image](diagnostic-before-palette-correction.png) is retained. The correction changes presentation only. The final images below use a fixed time range that includes the same load. They were captured after load and visually checked in both themes.

## Final images

| Dashboard | Light | Dark |
| --- | --- | --- |
| Operations | [PNG](cmtc-operations-light.png) | [PNG](cmtc-operations-dark.png) |
| Workload Security | [PNG](cmtc-workload-security-light.png) | [PNG](cmtc-workload-security-dark.png) |

[Render results](walk-results.json) report successful captures and explicitly blocked security capabilities. [Metric assertions](metric-assertions.json) check the actual inventory and live issuer source/lease. The lease shows a public producer's freshness. It does not show certificate consumption or encrypted traffic.

## Reproduction and limits

The capture image was built with host Podman for Linux ARM64. Its configuration ID is `sha256:f8fa226da31a7293d6ae31846344ac807f515c2679c4d167c8e7c35167e32b7a`. [The source manifest](source-manifest.json) records the exact file hashes used for this qualification. [The build log](capture-build-third.log) records the image build. [The deployment record](deployment.json) records the verified Grafana ConfigMap and dashboard hashes.

Run `python3 observability/build.py --check`. Run `python3 observability/validate.py`. Run `python3 -m unittest discover -s observability -p 'test_*.py'`. Run `node scripts/capture/dashboard-spec.test.cjs`. The local suite passes 19 dashboard tests. The separate load timeline and frozen collector suites pass 32 tests; their logs are retained here.

[Promtool results](promtool-result.json) record 13 test groups with 45 expression checks and eight alert checks. Tests cover absent sources, measured idle traffic, actual failures, counter windows, partition totals and typed coverage denominators. Failure-only TLS attempts give a measured zero success ratio. No attempts give no ratio. Idle histogram buckets give no percentile. These fixtures test query logic; they do not create runtime security evidence.

Native acceptance additionally requires two independently frozen node names per cluster, one reachable target and both workload-manager gauges per node, and successful closed connections in both directions with the exact configured source and destination trust domains. Duplicate targets cannot replace a missing node. Use `--node-a` twice and `--node-b` twice with `--expect-native`. The negative tests also require policy denial and reject unverified connections without a failure flag. These checks remain unavailable until the native profile is deployed.

No proxy, signer or application restart was required for the dashboard deployment. The original ConfigMap backups remain in the private local task directory. No private key or kubeconfig is included here. See [the panel review](../../../observability/DASHBOARD_REVIEW.md) for metric semantics and each presentation decision.
