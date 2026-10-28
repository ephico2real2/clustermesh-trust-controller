# Root pin retirement, 2026-10-27

Every node's ztunnel issuer pins (`/etc/cmtc/ztunnel-issuer-pins/pins.json`) pinned two roots: the retired CMTC Lab
Organization Root (`0c28af9e…4b7c`) and the mesh root (`6c12c735…275f`). This run removed the Lab Organization Root
from all four nodes of kind-cmtc-a and kind-cmtc-b without a checkpoint reset. Operator decision: "Root retirement in
ztunnel", over redoing the mTLS enabling.

State: **deployed and traffic-qualified** on both labs.

## Why

A CMTC node agent with `managePins` reports `WriteFailed` for a pin the approval does not name, and the issuer approval
arbiter refuses `WriteFailed` (`internal/controller/approval_evidence.go:303`). The old ztunnel (fork `0e92198`) could
add a root pin to its checkpoint origin but failed closed when one was dropped.

## What changed

| Component | Before | After |
|---|---|---|
| ztunnel image | `cmtc-ztunnel@sha256:6f1ae689…4f4a` (fork `0e92198`) | `cmtc-ztunnel@sha256:bc4fb925…7771` (fork `68c0282`, draft PR ephico2real2/ztunnel#2; CI image run 40560978570; arm64 config ID `f62ade9e…c338`) |
| Cilium release | cmtc-b revision 8, cmtc-a revision 8 | cmtc-b revision 10, cmtc-a revision 9: the ztunnel DaemonSet template image only ([cmtc-a plan](cmtc-a-plan.txt): 2 changes, 0 deletions, 0 refusals) |
| `pins.json` `rootPins` | [`0c28af9e…`, `6c12c735…`] | [`6c12c735…`] ([before and after](pins/), [records](pins/retired.jsonl)) |
| checkpoint `origin.root_pins` | [`0c28af9e…`, `6c12c735…`] | [`6c12c735…`] ([readback](checkpoints-after.txt)) |

Fork `68c0282` continues a checkpoint whose origin differs from the installation only by retired root pins, if the
recovered anchors still chain to a remaining pin. It refuses a retirement of the anchored root ("checkpoint root not
independently pinned"), any other origin change, and an add with a retire together.

## Order, per cluster (cmtc-b first, then cmtc-a)

1. `config/lab/cilium/ztunnel.yaml` names the new image; `scripts/lab/cilium_adopt.py upgrade`. The ztunnel DaemonSet
   is `OnDelete`, so no Pod changed ([cmtc-b](cmtc-b-pods-after-helm2.txt), [cmtc-a](cmtc-a-pods-after-helm.txt));
   `cilium_release.py check`: 0 differences.
2. Per node, worker first: `scripts/lab/issuer-profile/retire_root_pin.py` (the old file is kept on the node at
   `/etc/cmtc/ztunnel-issuer-pins-before-root-retirement.json`), then at once the ztunnel Pod replacement with its
   exact SPIRE delegate entry, then the node's Cilium agent restart ([ledger](ledger.jsonl)).

The image moves before the pins narrow: an old-image ztunnel that restarts on the narrow file fails closed. Rollback:
restore the kept file before any image rollback.

| Node | Pins narrowed | New ztunnel Ready, durable commit | Cilium agent restarted |
|---|---|---|---|
| cmtc-b-worker | 19:05:43.9Z | 19:05:46.9Z (`ztunnel-cilium-rxmwb`) | 19:07:42Z |
| cmtc-b-control-plane | 19:08:13.9Z | 19:08:17.0Z (`ztunnel-cilium-w6hrb`) | 19:08:43Z |
| cmtc-a-worker | 19:14:51.2Z | 19:14:54.7Z (`ztunnel-cilium-5l4kd`) | 19:15:27Z |
| cmtc-a-control-plane | 19:16:02.1Z | 19:16:05.7Z (`ztunnel-cilium-fg2qr`) | 19:16:20Z |

## Results

- Every new ztunnel logged `stage="installation-root-pin-retirement"` with `retired=["0c28af9e…"]`, then a durable
  commit at logical generation 6 ([extract](ztunnel-retirement-log.txt)).
- Checkpoints: version 2, logical generation 6, authority generation 6, predecessor generation 5. The sequence
  continued from the stored floors: the first commits of the new ztunnels were 18209 and 18224 (cmtc-b), 18256 and
  18263 (cmtc-a); the [readback](checkpoints-after.txt) shows 18318 (cmtc-b) and 18311 (cmtc-a). No checkpoint was
  reset.
- Each Cilium agent logged `stage=issuer-profile-source-succession` ("floors carried") and the issuer-profile ACK.
- clustermesh-apiserver restart count 0 on both clusters, the same Pod before and after.
- cmtc-a NodeTrustReports ([after](cmtc-a-nodetrustreports-after.txt)): pins `ReadOnly`, `rootSHA256` [`6c12c735…`];
  ztunnel `Accepted`, `acceptedGeneration` 6, `Validated`, `loadedRootSHA256` [`6c12c735…`]. cmtc-b runs the CMTC
  image without NodeTrustReports.
- CMTC node agents: 0 fence and 0 error lines from 19:05Z.
- Matrix after cmtc-b ([join](matrix-cmtc-b/join.txt), 19:09:34–19:13:36Z) and after both clusters
  ([join](matrix-all/join.txt), 19:16:53–19:20:55Z): 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium,
  0 failed.

## Observations

- During the agent restart, ztunnel logged reconnect warnings (`/var/run/cilium/ztunnel.sock` connection refused,
  xDS connect errors) for about 10 s, then received the ZDS snapshot.
- Each ztunnel logged 4 client-side `Error in HBONE connection handshake: PermissionDenied, "authenticated issuer
  profile/session expired or changed"` during the final matrix, each within 2 ms after a whole second. This is not
  new: the step-2 matrix before the retirement has 12 such lines
  ([approval-arbiter-20261027/matrix-step2](../approval-arbiter-20261027/matrix-step2/ztunnel-access/)), and
  [g1-destination-sources](../g1-destination-sources/README.md) records it as not yet explained. No probe failed.
- `--wait=watcher` never finishes for the `OnDelete` ztunnel DaemonSet (cmtc-b revision 9 failed after 15 minutes
  with "DaemonSet/kube-system/ztunnel-cilium not ready. status: InProgress"; objects applied, no Pod changed).
  `cilium_adopt.py` now uses `--wait=legacy`, which skips a DaemonSet that is not `RollingUpdate` (helm v4
  `pkg/kube/ready.go`); cmtc-b revision 10 and cmtc-a revision 9 finished in seconds.
