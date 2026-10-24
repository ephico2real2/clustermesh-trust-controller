# Deployed Observe validation

## Local two-page dashboard consolidation — October 24, 2026

All nine original domain JSONs are preserved byte for byte against `b68484a`; their coverage is combined into Operations (28 panels) and Workload Security (29 panels). Ten planned Operations signals and sixteen planned Security signals remain visible and explicitly BLOCKED. The twelve native mTLS panels retain their qualified query semantics. The [root dashboard guide](../../DASHBOARD_GUIDE.md) maps each original domain, defines chart meanings and shows both themes. This is local ARM64 qualification; the earlier CI runs below tested their recorded layouts.

The fresh baseline load completed 7,200/7,200 HTTP 200 responses in each cluster's shop and 3,600/3,600 across the remote-only Global Service: 18,000 total. A separate fresh cross-node mTLS run completed 3,000/3,000 via Service and 3,000/3,000 via Pod IP; 900/900 unenrolled attempts received no HTTP response. These remain distinct experiments. The baseline Cilium source is `42f89f83aa`; the isolated mTLS agent daemon reports `f052d1276b`.

The security screenshots use absolute UTC **05:48:03.361–05:53:03.361**, ending five seconds before the authenticated load jobs completed. Their destination-reported completed TCP pie partitions an estimated 6,890.743 connections: 86.665% authenticated without a failure flag, 13.335% unauthenticated and blocked, and zero in the other three categories. Counter increases are extrapolated estimates, so they need not equal the generators' exact request/attempt counts. TCP connections are not HTTP requests or TLS handshakes.

Both generated files match live Grafana panel JSON exactly. Real queries pass for both clusters and each selected separately; namespace categories sum to their denominator, the pie totals 100%, declared live metric types match, and absent telemetry remains empty. Both themes pass panel bounds and table-row checks after enlarging the namespace table. The browser walk passes all five rendering cases, with every missing planned signal recorded as BLOCKED rather than a successful feature. [Immutable full screenshots, raw load results, query vectors, image IDs, source definitions and checksums](https://github.com/ephico2real2/clustermesh-trust-controller/blob/87fb20341d62904d2536efc840b975a49458be23/2026-10-24T0558Z-cmtc-consolidated-dashboards/README.md) preserve the measured source `5d1ddc1008ff282309c8301437bea01f54a50712`. Full fail-closed, ClusterMesh workload mTLS and transport composition acceptance remain open.


## Earlier GHCR baseline

2026-10-23: [CMTC PR #4](https://github.com/ephico2real2/clustermesh-trust-controller/pull/4) merged the public GHCR bundle and separate Fortio JSON collection. [Feature-head CI 40043884931](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40043884931) passed at `dbb56598e5f7c64228c7a818e03188140f9e7b4c`; [merged-main CI 40046157600](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40046157600) passed at `90f6bc647a88a1c6b1b00fd0203a4b49f7537b83`.

Both clusters used our agent, generic operator and ClusterMesh API server digest pins with the chart/CRDs from image source `93041b3f7ec55ff12c83ecd266f14fb392ea5c93`. Runtime image IDs and agent source versions were asserted. The [final publisher run](https://github.com/ephico2real2/cilium/actions/runs/40041922977) passed, and anonymous registry reads confirmed AMD64/ARM64 in all three image indices.

The same scripts passed locally on this MacBook in the dedicated Colima Ubuntu 24.04.4 ARM64 VM (8 CPUs, 16 GiB, kernel 6.8.0-117-generic). Each cluster had two Ready nodes and reported 2/2 node connections plus 1/1 KVStoreMesh connections to its peer. Policy selection/exclusion, namespace recreation, conflict recovery, read-only RBAC, allowed/denied shop requests and the remote-only Global Service all passed. The default inotify instance limit of 128 caused a worker agent startup failure; raising it to 8192 resolved the failure and was persisted inside this lab VM.

| Six-minute local Fortio stream | Requests | HTTP 200 | Actual req/s |
|---|---:|---:|---:|
| Cluster A shop | 7,200 | 7,200 | 19.997 |
| Cluster B shop | 7,200 | 7,200 | 19.997 |
| Cluster A to remote-only B backend | 3,600 | 3,600 | 9.997 |
| Total | 18,000 | 18,000 | |

The feature-head AMD64 CI independently produced the same request counts and 100% HTTP 200 responses. All eleven browser pages rendered during active load; the Observe dashboard had data in all six panels, with four selected namespaces and two inventory agents per cluster and enforcement availability zero. The nine future security dashboards explicitly retained blocked feature-evidence verdicts. [Local screenshots, load JSON, mesh status and image proof](https://github.com/ephico2real2/clustermesh-trust-controller/tree/18d063335fb130770003c915cb1bed1ee87528fc/2026-10-24T0033Z_cmtc_local-macos-arm64) and [feature-head CI screenshots](https://github.com/ephico2real2/clustermesh-trust-controller/tree/e3c1584c12dc1445a63332084aaf4964914affa0/2026-10-24T0026Z_cmtc_run40043884931-1_deployed-lab) are immutable. The local Observe PNG was visually inspected.

This validates the GHCR-backed Observe/ClusterMesh baseline. ClusterMesh API TLS does not establish workload mTLS, authorization enforcement or WireGuard/IPsec composition.

## Authorization resource transport

The new development lock selects source `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`. [Publisher CI 40053175683](https://github.com/ephico2real2/cilium/actions/runs/40053175683) passed: the ARM64 set was built locally on this MacBook and reused by CI, AMD64 was built natively in GitHub, and all three component indices contain both platforms with matching source labels and actual agent binary versions. The chart and dashboard example source pin advance with those images; the dashboard generator/input/output hashes are unchanged. The [new local two-cluster qualification](https://github.com/ephico2real2/clustermesh-trust-controller/tree/67c7f0c1dda7916cef9cf3ba29c149b23f9d731e/2026-10-24T0237Z_cmtc_authorization_images_local-arm64) passed all policy/RBAC/remote-service checks, verified all three deployed image digests and agent versions, and returned 18,000/18,000 HTTP 200 responses over three six-minute streams. Eleven browser pages rendered during active load; all six Observe panels had data. The retained fixture namespaces were reset before the successful final regression. This remains an Observe/ClusterMesh baseline.

[Cilium PR #6](https://github.com/ephico2real2/cilium/pull/6), source `42f89f83aa5a03ea80f7a2b8cece56b27f87385a`, implements the typed Authorization desired-state cache and real Go delta ADS delivery. It reuses Cilium's existing delta engine for subscriptions, versions, ACK/NACK, removals and reconnect cleanup. Address and Authorization acknowledgment state remain separate and share a serialized gRPC writer. No policy producer is enabled.

Both the MacBook's Ubuntu ARM64 VM and [AMD64 CI 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200) passed 150 tests/subtests across bindings, ztunnel xDS and shared delta packages with the race detector, using Go 1.27.1. Vet, workflow lint and diff checks passed; CI also verified exact protobuf regeneration. [Immutable local evidence](https://github.com/ephico2real2/cilium/tree/4ba5fc1df930c6a062875628cfe3e090218cf96a/2026-10-24T0205Z_ztunnel_authorization_local-arm64) retains every test event and the digest-pinned Linux toolchain; the CI artifact retains corresponding source/toolchain/platform metadata and JSON events.

[Local follow-up validation](https://github.com/ephico2real2/cilium/tree/2a29f75e023cbcab8a8e23738295e771f3a98103/2026-10-24T0233Z_authorization_test_fix_local-arm64) at `cf34ab9ae795fa6f0e79fe86a30b0d21bb90185d` also passed golangci-lint 2.15.0, all 150 race tests/subtests and vet after correcting test imports and adopting `t.Context()`. Only test code differs from the published runtime image source.

Tests exercise the actual Go ADS handler over in-memory gRPC: validated immutable/atomic batches, update/delete, combined ACK/subscription changes, NACK/stale ACK, reconnect deletion, independent clients, Address coexistence, cross-type ACK rejection, node-ID changes and send failure. They do not run the Rust policy engine or encrypted workload traffic. Effective Cilium policy translation, workload policy references, authenticated remote discovery, cluster-bound issuance and persistent admission remain open; the compatibility guard and Observe-only schema remain.

## Imported PoC dashboard by app

The [example](../../examples/observability/hubble-l7-by-app/README.md) includes the exact demo 37 generator from PoC commit `22fb6e14c0cca8c78af1f072d1e89ebaea6a916b` and its output against the chart pinned by the GHCR lock. A checksum and regeneration check runs in the CMTC deployed-lab workflow. The separate Cilium Hubble qualification provisions this app dashboard beside the workload dashboard and uses different app/workload names to distinguish the two label families.

Gateway client series can retain source namespace/workload with an empty source app. The app dashboard therefore checks namespace selection with app All, and explicit source app selection with direct-pod traffic. Its original generator omits workload CPU panels, leaving nine HTTP panels. The historical remote-workload limitation in the generator comment predates upstream #48563; the current fork already contains that upstream fix.

The [local ARM64 qualification](https://github.com/ephico2real2/cilium/tree/b13bda7f2e4e30484b8caee2a7f02a180799c157/2026-10-24T0123Z_hubble_l7_by_app_local-macos-arm64) passed at helper head `c6b47722c1c4a1bd7ed8bdf62de553c4307943d7`, using the public source-matched GHCR agent/operator digests. Three fresh six-minute Fortio streams returned 151,200/151,200 HTTP 200 responses (72,000 external Gateway, 72,000 pod Gateway, 7,200 direct). All eleven browser cases passed, including all nine app panels and eleven workload panels without No data results. App All measured 399.960 requests/s, direct source app 19.980 and source namespace with app All 199.980. The copied generator hash, native agent version, deployed image references, actual Grafana 13.2.1 health response, raw load JSON and visually inspected PNGs are retained with the immutable evidence. [Focused AMD64 CI 40050031206](https://github.com/ephico2real2/cilium/actions/runs/40050031206) passed the corresponding fresh-cluster qualification with 151,063/151,063 HTTP 200 responses and eleven browser cases.

## Earlier released-image Observe evidence

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

These original tests establish a pinned protocol foundation only. That patch did not implement authorization resource delivery; the later transport slice is described above. Remote discovery, effective policy/admission and encryption remain open. Source-to-runtime-proxy interoperability remains unverified. Existing Hubble branches and the compatibility guard remain separate from this patch. The earlier release-base protocol evidence is [run 40022647528](https://github.com/ephico2real2/cilium/actions/runs/40022647528) at `636e441044379d48db0686eb21becf9351f782f6` (Go 1.26.10); it is historical, not validation of the current main port.

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
