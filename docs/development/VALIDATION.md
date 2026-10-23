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

[Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1), commit `636e441044379d48db0686eb21becf9351f782f6`, passed [focused CI run 40022647528](https://github.com/ephico2real2/cilium/actions/runs/40022647528): authorization descriptor/independent wire fixture/Any type-URL and JSON tests under the race detector, `go vet`, checksum-verified protoc tools and reproducible regeneration. The inherited patch/signoff and workflow checks also passed. The Go generators are built with Go 1.26.10 to keep comment formatting reproducible.

These tests establish a pinned protocol foundation only. The patch does not implement authorization resource delivery, remote discovery, runtime policy/admission or encryption. The inherited image-publishing workflow is separately blocked by a Quay OIDC-token HTTP 401; no successful Cilium image build or deployment is claimed from this run. Existing Hubble branches and the compatibility guard remain separate from this patch.

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
