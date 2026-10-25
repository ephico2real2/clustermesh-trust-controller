# Local activation evidence — October25

This bundle records the rebuilt-image rollout, strict ZDS PID-namespace recovery,
72 successful baseline requests and the first failed enrolled request in each
cluster. It does not establish working end-to-end workload mTLS.

Read [handover.md](../../../handover.md) for exact state and next actions.
[manifest.json](manifest.json) lists public evidence files and SHA256 checksums.
Private keys, kubeconfig credentials and large image archives are excluded.

- `operations/`: retained build, deployment and test scripts. Review their
  source pins and ownership guards before use. Do not replay bootstrap stages
  against existing state.
- `raw/`: build/image receipts, public configuration audits, current errors and
  ClusterMesh status. Text/log files may be gzip-compressed.
- `live-tests/`: namespace/Pod/entry ledgers, app manifests, request results,
  public xDS dumps and Prometheus snapshots. These are measured results, including failures.

The runner's original `proposal` filename does not mean every stage is unrun.
Create/register/enroll ran on both clusters. Both36-request baseline matrices
passed. Each enrolled first-path run failed on its first request. The remaining
encrypted traffic matrix, denial/recovery/load and screenshots remain open.

The scripts contain machine-local paths. Existing UID/resourceVersion checks
and one-time bootstrap guards are intentional. Preserve the original live run
ledger and checkpoints instead of making them match by deletion.
