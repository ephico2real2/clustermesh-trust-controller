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
reconciler. Use the Ubuntu toolchain for Linux datapath tests. After the live path works,
deploy the image that CI publishes to `ghcr.io/ephico2real2`, by digest, then
qualify that exact image. Do not side-load images (`kind load`, `ctr import`).
Read [API access](handover.md#reach-and-test-the-cluster-apis-from-the-macbook)
for endpoints, VM/build access and loopback limitations. Never print kubeconfig
credentials or disable API TLS verification.

## Current state (2026-10-27 13:50 UTC)

Read the [2026-10-27 update in handover.md](handover.md#update-2026-10-27-1350-utc-claude-code-session-b744973a)
for the evidence. In short:

- Workload mTLS is traffic-qualified on both clusters: same node, cross node, cross cluster, Pod IP, per-Pod name
  and Global Service; unregistered callers are dropped. Not a `Protected` claim.
- SPIRE signs under `<cluster>-spire-intermediate` and the mesh root (issue #34). cert-manager requests are approved
  by policy.
- Issuer approval generation 6 expires 2026-11-25T10:26:41Z. No renewal is automated; at expiry the lab fails
  closed. No host-side stopgap is kept (operator, 2026-10-27).
- In progress: the CMTC controller as the arbiter of trust changes, with the node agent reporting per-node
  evidence. Unreviewed work in progress on branch `feat/approval-follows-cert-manager`. Brief:
  `/private/tmp/cmtc-opus-final-20261025/review/approval-reconciler/BRIEF.md`.

## First actions

1. Verify the Git HEADs and dirty files in the root, the arbiter worktree and the three fork checkouts.
2. Verify that no earlier session, agent or compiler is still running.
3. Claim the source/compiler/live lease before making changes.
4. Verify both kube-system UIDs, that both clusters publish generation 6, and the time left before it expires.
5. Read the arbiter brief in full, with every amendment, and ADR-012 on the arbiter branch.
6. Have the arbiter branch reviewed independently (precise claims, file:line), then fix the findings.
7. Add the missing parts: the chart and RBAC, the node-report write enforcement, the cross-cluster path.
8. Test against cmtc-b, then cmtc-a: renewal, intermediate key rotation with overlap, controller restart, a
   missing node report.
9. Run the mTLS matrix (`scripts/evidence/run_mtls_matrix.sh`) after each cluster.
10. Port the lab-managed configuration to Helm (#33).

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
commands, builds and failed traffic (2026-10-25, historical). `resume-opus.md` is retained history;
this file and handover.md take precedence at this handoff.

The user authorized committing all work and personal-default merges while
retaining every working branch. Verify actual refs before publication. Manual
CI dispatch, registry publication, canonical upstream merges and force pushes
are not included. Preserve signer state, private keys and unrelated apps.
