# Deployed Observe validation

## Current evidence

2026-10-23: [CI run 40020608206](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40020608206) passed both jobs at implementation commit `f81b955948d33ad187ed6891aca7c348ec27197e`.

- Both clusters passed policy/inventory, application allow/deny and remote Global Service assertions. The expected unsupported-Strict rejection is now explicitly reported as a passing negative test; the complete API response is retained per cluster.
- The Ubuntu Playwright image passed YAML/JSON and variable handling, unexpected-empty-panel rejection, missing-text rejection and failure-screenshot smoke tests.
- All eleven deployed pages rendered. The nine future domain dashboards report missing security signals as **BLOCKED**, separately from rendering. The live Observe dashboard's six panels and imported application passed their feature assertions.
- Real telemetry again showed four selected namespaces and two inventory agents per cluster, with enforcement available **zero**. The latest Observe screenshot was visually inspected.
- [Published PNGs, browser log and per-page verdicts](https://github.com/ephico2real2/clustermesh-trust-controller/tree/2bffe855cf6adfe3a5b1fb7b9db986dc3d275514/2026-10-23T2049Z_cmtc_run40020608206-1_deployed-lab) are tied to an immutable publication commit. Artifacts also contain `results.json`, `walk-results.json`, metric assertions and strict-rejection responses.

This remains Observe/baseline evidence. Neither the successful job nor a rendered screenshot validates workload mTLS or layered WireGuard/IPsec encryption.

## Cilium protocol foundation

[Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1) is merged at `a035a5892526afa2235b690c62c2f004b72aa9ab`. Its signed-off feature head is `641288d50ad81be95b510b3fcd7c81cb085fa962`, ported to upstream main `3b6e980b3d4eaa5be4532602ccb2bd54d8540dc4` with Go 1.27.1 generators. Fork main additionally includes upstream `e5967e950b8f10ae514c58787e80d8e0192c15fd`.

- [Focused feature CI 40029705477](https://github.com/ephico2real2/cilium/actions/runs/40029705477) and [merged-main CI 40033037552](https://github.com/ephico2real2/cilium/actions/runs/40033037552) passed authorization descriptor/independent wire fixture/Any type-URL and JSON race tests, vet, checksum-verified protoc and exact regeneration.
- Feature-head [Go checks](https://github.com/ephico2real2/cilium/actions/runs/40029711817), [Cilium/Hubble/BPF/Ginkgo compilation](https://github.com/ephico2real2/cilium/actions/runs/40029711800), [generated documentation](https://github.com/ephico2real2/cilium/actions/runs/40029711830) and [Cilium CLI binary builds](https://github.com/ephico2real2/cilium/actions/runs/40029711767) passed. Patch/signoff and workflow checks passed.
- Inherited upstream image publishing fails at Quay OIDC-token acquisition with HTTP 401 before compilation. The normal fork merge used exact-head matching and no branch-rule bypass. Duplicate post-merge matrices were canceled in favor of the focused merged-main test and dedicated real-load workflow.

These tests establish a pinned protocol foundation only. The patch does not implement authorization resource delivery, remote discovery, runtime policy/admission or encryption. Source-to-runtime-proxy interoperability remains unverified. Existing Hubble branches and the compatibility guard remain separate from this patch. The earlier release-base protocol evidence is [run 40022647528](https://github.com/ephico2real2/cilium/actions/runs/40022647528) at `636e441044379d48db0686eb21becf9351f782f6` (Go 1.26.10); it is historical, not validation of the current main port.

## Real-load Hubble dashboard evidence

[Cilium fork PR #2](https://github.com/ephico2real2/cilium/pull/2) is merged at `33ab097444ac942f10606e236678bf55f6a9d498`. Its minimal dashboard head `e00be3729bf71334a500b5202a8e1136177697b3` changes only the two source variables' All regex to `.*`; workload/CPU queries and the addon symlink are preserved. Upstream's remote-workload fix is already merged as cilium/cilium#48563, so the September app-label workaround was not ported.

[Real-load CI 40032696185](https://github.com/ephico2real2/cilium/actions/runs/40032696185) passed after building the fork agent/operator and deploying their exact chart and CRDs in two-node kind. The backend ran on the control-plane node and Gateway Envoy on the worker; worker metrics retained the remote backend workload. Six-minute external Gateway and pod Gateway streams each requested 200 req/s, with a separate 20 req/s direct-pod stream. The saved external Fortio result had 71,944 HTTP 200 responses and the direct-pod result had 7,200, with no errors in either. The original capture run did not separately retain the pod-Gateway generator JSON; its stream is visible in real metrics. The final reusable CI test below retains and verifies all three streams separately.

Real Grafana responses showed baseline All at 199.933 req/s versus fixed All at 399.033 req/s grouped by destination, and 199.567 versus 399.600 grouped by source. Explicit direct-pod selection with the server reporter remained 20 req/s. All six browser cases passed, all eleven dashboard panels had data, and the PNGs were visually inspected. [Immutable gallery and query/assertion JSON](https://github.com/ephico2real2/cilium/tree/b2edb06a7ef4d522c1891e87f5b2b1174361360e/2026-10-23T2230Z_hubble_l7_run40032696185-1_dashboard); the run artifact also retains Hubble metrics/HTTP flows, scrape targets, image IDs, deployed version, placement, load results and logs. Eight Prometheus 3.10.0 fixtures remain supplementary query tests, not application traffic.

[Reusable fork CI PR #3](https://github.com/ephico2real2/cilium/pull/3) is merged at `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`, including upstream `fe561573e0a8adc43bacbcc70bda0c9e01d6676d`. [Combined-source run 40035107452](https://github.com/ephico2real2/cilium/actions/runs/40035107452) passed at `221d435ecce12fdf19efb4ca71026ff1c889317b` with the protocol foundation, dashboard fix and current upstream sync. The tested and merged source trees are identical.

| Six-minute Fortio stream | Requests | HTTP 200 | Actual req/s |
|---|---:|---:|---:|
| External Gateway | 71,958 | 71,958 | 199.863 |
| Pod Gateway | 71,962 | 71,962 | 199.874 |
| Direct pod | 7,200 | 7,200 | 19.997 |
| Total | 151,120 | 151,120 | |

All seven browser cases passed: baseline/fixed All grouped by destination and source, selected direct-pod/server source, selected pod-Gateway/client source and the dashboard overview. Fixed All measured 399.833 req/s versus baseline 199.600 grouped by destination, and 400.000 versus 199.933 grouped by source. Explicit pod-Gateway selection remained 199.800 and direct-pod selection 20.000. The browser requires the fixed result to include the measured external increment and explicit sources to retain their measured total. A nonempty graph alone cannot pass. All eleven panels had data. [Final immutable gallery and query/assertion JSON](https://github.com/ephico2real2/cilium/tree/22b2e5a023bd810af4fefd49032d3f4c9d053347/2026-10-23T2300Z_hubble_l7_run40035107452-1_dashboard); overview and destination PNGs were visually inspected. Artifacts include every Fortio JSON, raw metrics/flows, scrape targets, image/version/placement proof and logs. Internal PRs and manual exact-SHA runs can reuse the workflow on fork main; external fork PRs do not receive publication permissions.

The test deliberately uses HTTP to isolate dashboard matching. Workload mTLS, transport encryption, trust rotation and CPU query semantics remain unqualified by these runs. Upstream submission still requires the operator's personal review and own description under [Cilium's AI policy](https://github.com/cilium/community/blob/main/AI-POLICY.md); no upstream PR or automatic upstream merge has been created.

## Earlier deployed baseline

2026-10-23: [CI run 40018509010](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40018509010) passed both unit and deployed-lab jobs at implementation commit `568f7f7afe3d6381a87e2acff465edd8a5da7f29`.

- Go unit/race tests, vet, build, generated schema, formatting and manifest rendering passed.
- Two kind clusters deployed Cilium v1.20.4, cert-manager v1.21.1, cluster-local intermediate keys/public root trust, ClusterMesh, CMTC and monitoring.
- Policy selection/exclusion/platform precedence, namespace recreation, conflict/recovery, expected Strict rejection and read-only RBAC passed.
- Imported shop POS traffic succeeded, stranger traffic was denied in both clusters, and the Global Service returned the remote-only poc2 backend.
- The prepared Ubuntu browser image passed real browser smoke tests. All eleven deployed pages met their expectations: nine domain dashboards, the live Observe dashboard and imported app.
- Measured selected namespaces: 4 per cluster; inventory agents: 2 per cluster; enforcement available: 0 per cluster. The live Observe page had six panels and no missing data. Future security panels remained explicitly unknown.

[Published PNGs and browser evidence](https://github.com/ephico2real2/clustermesh-trust-controller/tree/136e05b1d4e4b2b4ad9e409330c5258951488563/2026-10-23T2031Z_cmtc_run40018509010-1_deployed-lab) are linked immutably from the run summary. The run artifact contains assertions, screenshots, logs, inventory, image IDs and source commit. The live Observe screenshot was visually inspected.

This verifies an Observe implementation and baseline Cilium policy/ClusterMesh. **Workload mTLS, SPIRE workload issuance/trust rotation and required WireGuard/IPsec composition are not implemented or validated.** The machine-readable results mark encrypted profiles blocked. Later source changes need their own recorded validation; this evidence is tied to the commit above.
