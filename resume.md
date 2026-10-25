# Resume CMTC

Read [handover.md](handover.md) first. It is the current operational record.
Then read `AGENTS.md`, `docs/handover/CODEX_MASTER_PROMPT.md` and the security
matrix. Older checkpoints saying ztunnel is off are superseded.

## Ultimate objective

Finish fail-closed workload mTLS across the two-cluster Cilium mesh. Use our
enhanced `ephico2real2/cilium`, `ephico2real2/ztunnel` and `ephico2real2/spire`
forks with this CMTC project. Keep node proxies and no application sidecars.
Complete native discovery, cluster-bound identity, effective authorization,
mandatory capture, withdrawal and recovery. Then qualify the selected
WireGuard/IPsec composition and real dashboard telemetry. Repairing startup or
one HTTP request is not completion. Read the detailed acceptance in handover.md.

## Reach the existing APIs

Run from the MacBook host:

```bash
cd /Users/olasumbo/gitRepos/clustermest-trust-controller
export KUBECONFIG=/private/tmp/cmtc-a-b-20261024.kubeconfig
kubectl --context kind-cmtc-a get --raw=/readyz
kubectl --context kind-cmtc-b get --raw=/readyz
kubectl --context kind-cmtc-a get nodes -o wide
kubectl --context kind-cmtc-b get nodes -o wide
```

Verify both kube-system UIDs against handover.md before mutations. Develop
directly against these explicit APIs where supported. Avoid a second active
reconciler. Use the Ubuntu toolchain for Linux datapath tests. Package with host
Podman only after the live path works, then qualify the exact deployed image.
Read [API access](handover.md#reach-and-test-the-cluster-apis-from-the-macbook)
for endpoints, VM/build access and loopback limitations. Never print kubeconfig
credentials or disable API TLS verification.

## Current state

- Ztunnel runs on all four nodes in `cmtc-a` and `cmtc-b`.
- Cilium and proxy host PID settings are corrected and explicitly approved.
- Both clusters passed36/36 baseline requests before test enrollment.
- Both `cmtc-live-mtls` namespaces are now enrolled.
- Both first enrolled requests failed with curl56 and no HTTP200.
- Strict xDS rejects Address updates and resyncs. A has unavailable current
  authorization; B drains the attempted HBONE connection.
- Membership/drain and native ZDS ownership errors remain.
- ClusterMesh reports0/1 remote Ready despite synchronized remote inventory.
- Cross-cluster workload mTLS is unproven. Preserve all security checks.

## First actions

1. Verify current Git HEADs and dirty files in the root and three fork checkouts.
2. Verify no previous task-owned Opus process or compiler is still running.
3. Claim the single source/compiler/live lease before making changes.
4. Check approval/certificate expiry and preserve existing checkpoints.
5. Read the failed run logs and xDS dumps in the committed activation evidence.
6. Reproduce the first enrolled request using the existing run ledger.
7. Repair strict xDS snapshot/update ordering and the associated membership lifecycle.
8. Add deterministic rejection and recovery regression tests.
9. Test the working source against the existing cluster fixture.
10. Package with host Podman and deploy the exact image.
11. Repeat same-node, cross-node and both cross-cluster directions.
12. Collect peer, policy, packet, load and dashboard evidence.

Keep each procedural action separate. Do not rebuild every image for a chart-only
change. Do not remove auth/policy guards to get an HTTP200. A network timeout
alone does not prove an identity denial.

## Locations

```text
Root:       /Users/olasumbo/gitRepos/clustermest-trust-controller
Forks:      /private/tmp/cmtc-opus-final-20261025/{cilium,ztunnel,spire}
Operations: /private/tmp/cmtc-primary-operations-20261025
Run ledger: /private/tmp/cmtc-primary-operations-20261025/live-mtls-test
Kubeconfig: /private/tmp/cmtc-a-b-20261024.kubeconfig
Contexts:   kind-cmtc-a, kind-cmtc-b
Grafana:    http://127.0.0.1:13000
```

Use [installation requirements](INSTALLATION_REQUIREMENTS.md) for hostPID and
[the activation receipt](docs/evidence/local-activation-20261025/README.md) for
commands, builds and failed traffic. `resume-opus.md` is retained history;
this file and handover.md take precedence at this handoff.

The user authorized committing all work and personal-default merges while
retaining every working branch. Verify actual refs before publication. Manual
CI dispatch, registry publication, canonical upstream merges and force pushes
are not included. Preserve signer state, private keys and unrelated apps.
