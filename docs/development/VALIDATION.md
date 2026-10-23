# Deployed Observe validation

2026-10-23: [CI run 40018509010](https://github.com/ephico2real2/clustermesh-trust-controller/actions/runs/40018509010) passed both unit and deployed-lab jobs at implementation commit `568f7f7afe3d6381a87e2acff465edd8a5da7f29`.

- Go unit/race tests, vet, build, generated schema, formatting and manifest rendering passed.
- Two kind clusters deployed Cilium v1.20.4, cert-manager v1.21.1, cluster-local intermediate keys/public root trust, ClusterMesh, CMTC and monitoring.
- Policy selection/exclusion/platform precedence, namespace recreation, conflict/recovery, expected Strict rejection and read-only RBAC passed.
- Imported shop POS traffic succeeded, stranger traffic was denied in both clusters, and the Global Service returned the remote-only poc2 backend.
- The prepared Ubuntu browser image passed real browser smoke tests. All eleven deployed pages met their expectations: nine domain dashboards, the live Observe dashboard and imported app.
- Measured selected namespaces: 4 per cluster; inventory agents: 2 per cluster; enforcement available: 0 per cluster. The live Observe page had six panels and no missing data. Future security panels remained explicitly unknown.

[Published PNGs and browser evidence](https://github.com/ephico2real2/clustermesh-trust-controller/tree/136e05b1d4e4b2b4ad9e409330c5258951488563/2026-10-23T2031Z_cmtc_run40018509010-1_deployed-lab) are linked immutably from the run summary. The run artifact contains assertions, screenshots, logs, inventory, image IDs and source commit. The live Observe screenshot was visually inspected.

This verifies an Observe implementation and baseline Cilium policy/ClusterMesh. **Workload mTLS, SPIRE workload issuance/trust rotation and required WireGuard/IPsec composition are not implemented or validated.** The machine-readable results mark encrypted profiles blocked. Later source changes need their own recorded validation; this evidence is tied to the commit above.
