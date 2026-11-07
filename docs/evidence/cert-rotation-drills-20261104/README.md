# Rotation drills, 2026-11-04 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

State: **measured** (the records below). No drill on this date qualifies a credential renewal: from 08:37Z every allowed
connection on both clusters failed, because ztunnel stopped renewing workload certificates
([ztunnel certificate refresh](../ztunnel-cert-refresh-20261104/README.md)). The drills run again after the fixed
ztunnel is deployed.

| Record | Result |
|---|---|
| [R1 on cmtc-a](R1-cmtc-a/README.md), 08:43:34Z to 08:46:03Z | **failed**: 149 of 149 probes failed on each of the 12 allowed paths, 0 of 75 answered on each denied path. The cause is the ztunnel outage, not the R1 renewal ([stdout.json](R1-cmtc-a/stdout.json)) |
| [Helm drift check](#helm-drift-check-for-the-negative-drills), 09:47:42Z to 09:47:53Z | 0 changes, 0 deletions, 0 kubectl manager entries, 0 refusals on both clusters, with the image values of the committed lock |

## Helm drift check for the negative drills

`scripts/evidence/rotation_drill.py` now runs `scripts/lab/cilium_adopt.py plan` before neg-ca and neg-pin, and
refuses unless it reports 0 changes, 0 deletions, 0 kubectl manager entries and 0 refusals. After the event it runs
`cilium_adopt.py transfer` (the drill's field manager `cmtc-rotation-drill` gives its fields back to Helm) and the
same plan, which must report 0 again. The dry runs at 09:40Z to 09:46Z (no `--execute`, nothing changed) passed this
check on both clusters for both drills.

The plan reads `config/lab/cilium/base.yaml` and `ztunnel.yaml` at `0cff841`, the chart at Cilium fork `1bd555f313`
and the cluster values that `cilium_cluster_values.py` wrote for each cluster. The image values decide the result:

| Image values | cmtc-a | cmtc-b |
|---|---|---|
| [`prepare.py` on the committed `config/cilium-images.lock.json`](helm-drift-check/cilium-image-values-0cff841.json) | [0 changes](helm-drift-check/cmtc-a-plan-lock-image-values.txt) | [0 changes](helm-drift-check/cmtc-b-plan-lock-image-values.txt) |
| `.tmp/cilium-image-values.json` of the operator checkout, written 2026-10-28T07:39Z | [8 changes](helm-drift-check/cmtc-a-plan-stale-image-values.txt) | [8 changes](helm-drift-check/cmtc-b-plan-stale-image-values.txt) |

The 8 changes are the agent image of DaemonSet `cilium` (the agent and its six init containers, and the template
generation): the live agents run `cilium-dev@sha256:36909012…`, the lock's digest since `35e32fd` (2026-10-28 19:26Z);
the older file names `cilium-dev@sha256:c77bdc52…`, the lock's digest from `ee7aa93` until then. A `cilium_adopt.py upgrade` with the default `--image-values`
from that checkout would therefore put an older agent on every node. Before any upgrade, run
`scripts/cilium/prepare.sh` (or `prepare.py` on the lock) and check that `plan` reports only the intended change.
