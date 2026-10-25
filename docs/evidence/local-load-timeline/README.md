# Local screenshots during eight-stream load

The MacBook Podman trial passed on 2026-10-25. It captured both CMTC dashboards in both themes at three points while the same eight Fortio processes ran. All 12 PNGs were inspected. [The timeline](timeline-results.json) records pre/mid/post checks and fixed query windows. Each round includes raw Prometheus results and browser verdicts.

All eight six-minute streams passed: 28,800 requests and 28,800 HTTP 200 responses. Fourteen thousand four hundred requests crossed the cluster boundary; fourteen thousand four hundred used the local shop services. Cross-cluster streams used TCP/80, 8080 and 31337 in both directions. Read [the measured per-stream results](load/load-results.json).

The capture image is Linux ARM64, configuration `0ca9ec0f1632bd777d833833ca23c5c863d366fb72f1dd74fc70007594a60d71`. [Source hashes and limits](summary.json) identify the copied image inputs. The build ran the Chromium smoke and browser fixture tests. The timeline and cleanup suite passes 23 tests with no skips. Nine collector tests also pass. The [final collector replay](frozen-collect.log) verifies the same frozen processes before and after reading logs by exact Pod name; it stages results until all eight pass. The real forced process-group kill test also passes; its first failure found Podman's default ten-second stop delay. The bounded recovery now uses an explicit zero-second Podman stop. Unrelated containers remain intact.

The first local capture failed because the Colima VM does not mount the repository under `/Users`. The successful repeat used identical scripts under the existing shared `/private/tmp` mount. The failed attempt and original cleanup failure remain here as diagnostics. No cluster was recreated.

These are Observe screenshots. Operations has real inventory and reconciliation data. The security page records unavailable native mTLS and planned signals accurately. Combined ClusterMesh workload mTLS remains disabled; these HTTP results do not prove TLS or authorization.

| Round | Operations | Workload Security |
| --- | --- | --- |
| 45 seconds | [Light](round-01/cmtc-operations-light.png) · [Dark](round-01/cmtc-operations-dark.png) | [Light](round-01/cmtc-workload-security-light.png) · [Dark](round-01/cmtc-workload-security-dark.png) |
| 135 seconds | [Light](round-02/cmtc-operations-light.png) · [Dark](round-02/cmtc-operations-dark.png) | [Light](round-02/cmtc-workload-security-light.png) · [Dark](round-02/cmtc-workload-security-dark.png) |
| 225 seconds | [Light](round-03/cmtc-operations-light.png) · [Dark](round-03/cmtc-operations-dark.png) | [Light](round-03/cmtc-workload-security-light.png) · [Dark](round-03/cmtc-workload-security-dark.png) |
