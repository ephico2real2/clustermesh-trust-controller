# Resume CMTC

Read [handover.md](handover.md) first. It is the current operational record.
Then read `AGENTS.md`, `docs/handover/CODEX_MASTER_PROMPT.md` and the security
matrix. Older checkpoints saying ztunnel is off are superseded.

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
