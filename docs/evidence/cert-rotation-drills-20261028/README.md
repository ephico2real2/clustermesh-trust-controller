# Certificate rotation drills on kind-cmtc-b, 2026-10-28 (#47 Phase 2, #46)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Result: the Cilium agent of kind-cmtc-b moved to the build with the origin-session renewal change (Cilium fork
`ce5c3ec031`, image `ghcr.io/ephico2real2/cilium-dev@sha256:8446cf910bdba8d0ef7760693a16b8536800de6e353456df6e6f7bca8969b2cc`)
through Helm (release `cilium` revision 12, 16:25:46Z to 16:26:16Z, drift check 0 afterwards). Under one probe per
second on 14 paths (every scope, both clusters, both directions, plus the unregistered caller), the four credential
renewals of #47 rows R1 to R4 on cmtc-b cost **0 failed probes** and caused **no withdrawal** on any agent. R1, the
renewal of `ztunnel-origin-reader` that #46 is about, was taken up by both cmtc-b agents as
`Direct-origin transport refreshed in place` (2.5 ms and 2.2 ms), where the previous build withdrew the peer for
0.3 s to 10 s. kind-cmtc-a was not touched: its agents stay on `823d30c51b` until the predicted server-leaf-expiry
withdrawal at about 21:51Z is measured.

State: **deployed and traffic-qualified on kind-cmtc-b**; **not deployed on kind-cmtc-a**. Design and code:
[MESH_CERTIFICATE_RENEWAL.md](../../architecture/MESH_CERTIFICATE_RENEWAL.md). Drill tool:
[`scripts/evidence/rotation_drill.py`](../../../scripts/evidence/rotation_drill.py). Each drill directory holds
`summary.json` (everything, including the verdicts), `traffic.jsonl` (one row per probe, host-stamped),
`plan.json`, `preflight.json`, `README.md` and `logs/*.events` (the Cilium agent and ztunnel lines that matter;
the raw log copies were not kept). The matrix directory is a `run_mtls_matrix.sh` record.

Later the same day: cmtc-a moved to the same build (revision 11, 17:23Z), the session renewal at the peer's server certificate end was measured on both clusters, and an outage on cmtc-a showed that the R3 result below was a false pass: [server-leaf-expiry](server-leaf-expiry/README.md).

## Upgrade of kind-cmtc-b

1. The lock: `config/cilium-images.lock.json` `images.agent` set to the digest above (tag
   `sha-ce5c3ec031b412a4b927bcba025f9ef269a41673-agent`, `source_sha ce5c3ec031…`); chart source `1bd555f313`
   unchanged. `scripts/cilium/prepare.sh`, `cilium_cluster_values.py … cmtc-b --from-live`.
2. Finding: the committed `config/lab/cilium/base.yaml` does not hold the Cilium Ingress and L2 announcement
   settings that revision 11 (02:40Z) was deployed with from the operator checkout's uncommitted copy; a render from
   the committed file showed 28 differences and 7 deletions (the ingress objects). The render for this upgrade used
   a copy of that uncommitted `base.yaml` (SHA-256 `ca99e6ed33099a92…`), which is not committed here because it is
   not this work's. With it, `cilium_release.py check --strict`: 7 differences, all the agent image in the `cilium`
   DaemonSet pod template (the agent container and its six init containers).
3. `cilium_adopt.py plan`: 8 changes (those 7 and the server-maintained generation annotation), 0 deletions, 0
   kubectl manager entries, 0 refusals ([plan](upgrade-cmtc-b/plan-cilium-adopt.txt),
   [check before](upgrade-cmtc-b/check-before.txt), [check after](upgrade-cmtc-b/check-after.txt),
   [helm output](upgrade-cmtc-b/helm-upgrade.txt)). No other pod template changed; the clustermesh-apiserver Pod
   (`clustermesh-apiserver-657779cb9c-bcw9l`, since 2026-10-26 17:28Z) has 0 restarts after the upgrade; the ztunnel
   Pods (2026-10-27 19:05Z and 19:08Z) were not replaced, so no SPIRE delegate entry was needed.
4. `cilium_adopt.py upgrade` 16:25:46Z to 16:26:16Z under the drill's traffic watch (`upgrade-cmtc-b`, 420 s):
   revision 12; the control-plane agent ready at 16:26:06Z, the worker agent at 16:26:24Z, both logging
   `Cilium 1.21.0-dev ce5c3ec0` and `cilium-dbg version` Daemon `ce5c3ec0`; each projected cmtc-a within 10 s of
   its start (16:26:14Z, 16:26:35Z). `cilium_release.py check` after: 0 differences, 0 to delete, 0 to take over.
5. The watch: 4991 allowed probes, 199 failed, every failure between 16:25:54Z and 16:26:35Z, the two agent restart
   windows (an agent restart withdraws and re-projects the peer, as every earlier agent rollout did); none after
   16:26:36Z. 420 probes from the unregistered callers, 0 answered.
6. Matrix 16:33:34Z to 16:35:29Z ([join](matrix-cmtc-b-after-upgrade/join.txt)): 95 proven over mTLS, 0 unanswered,
   34 dropped by Cilium at `bpf_lxc.c:2381`, 1 "failed": the first probe (cmtc-a `client-worker` to its same-node
   server, HTTP 200 from the expected Pod) has no ztunnel outbound line for its socket `10.10.1.205:41500` in the
   extract, so the join could not prove it (the same kind of row as the 96th of the generation-6 matrix). The cmtc-b
   `negative-name` run stopped after 10 of 12 rows, all denied (curl 28): the fixture client containers run
   `sleep 86400` and the kubelet restarted them at 16:35:28Z (daily since 2026-10-25; the cmtc-a clients restart at
   17:43Z), which ended the probe's exec with code 137. That is a fixture artefact, not traffic; 34 of 36 denied
   probes were recorded.

## Drills R1 to R4 on kind-cmtc-b

Each: `rotation_drill.py drill <R> --cluster cmtc-b --seconds 150 --lead 20 --execute`. The event is `cmctl renew`
of the named Certificate(s) in `kube-system`; the probe window is 150 s with 20 s before the event.

| Drill | Certificate(s), renewal time, revision | Allowed probes / failed | Denied probes / answered | Agent events |
|---|---|---|---|---|
| R1 | `ztunnel-origin-reader` 16:39:24Z, 4 to 5 | 1794 / 0 | 150 / 0 | both cmtc-b agents `refresh-origin-transport` reason `client credential renewed` at 16:39:55Z (2.47 ms) and 16:40:15Z (2.19 ms), `leaseEnd=2026-10-29T13:48:06Z` (cmtc-a's server leaf NotAfter, the earlier bound); 0 `event=withdrawn` |
| R2 | `ztunnel-membership-writer` 16:42:20Z, 4 to 5 | 1791 / 0 | 150 / 0 | none |
| R3 | `cmtc-ztunnel-ads-server` 16:45:21Z, 4 to 5 | 1794 / 0 | 150 / 0 | none; the ztunnel workload certificates renewed in the window (serials changed on both cmtc-b ztunnels), no xDS stream event |
| R4 | `clustermesh-apiserver-{admin,local,remote,server}-cert` 16:48:26Z to 16:48:56Z, 7 to 8 (server key kept) | 1788 / 0 | 150 / 0 | none on either cluster |

The 31 s and 51 s between the R1 renewal and the refreshes are the kubelet's projected-volume update interval; the
agent polls the files every 2 s and refreshed within the next poll of seeing them.

Expected, not a refutation: the new cmtc-b agents opened their sessions at 16:26Z on cmtc-a's revision-7 server
leaf (NotAfter 2026-10-29T13:48:06Z), so the withdrawal that the design note predicts for the previous build at
21:48:06Z will not happen on cmtc-b. The cmtc-a agents, still on `823d30c51b`, remain the evidence for the
prediction at about 21:51:07Z (cmtc-b's revision-7 leaf; R4 issued revision 8 at 16:48:56Z, which those agents see
only at their next handshake).

Observed on both clusters, including untouched cmtc-a, and not caused by this change: the ztunnel of each worker
logs 4 to 7 times per 150 s `Error in HBONE connection handshake: … PermissionDenied … "authenticated issuer
profile/session expired or changed"` on the enrolled `client-worker`'s outbound, with 0 failed probes. Not
investigated here.

Not run today: R5, R6 and the negative drills (wrong CA, wrong pin, peer down) wait until both clusters run the new
build (coordinator, 2026-10-28). Rollback, not needed: the lock back to `c77bdc52…ac8a447` (`823d30c51b`) through
the same Helm path.

## Tables

### upgrade-cmtc-b: R6 on cmtc-b, 16:25:39Z, window 420 s

Event: 16:25:47Z. Allowed probes: 4991, failed 199; denied probes: 420, answered 0.

| Path | Requests | Failures | Longest run |
|---|---|---|---|
| `cmtc-a-crosscluster` | 415 | 17 | 16:26:15.762-16:26:33.837 (17, 28/000,56/000) |
| `cmtc-a-crossnode` | 418 | 0 | - |
| `cmtc-a-denied` | 210 | 0 | - |
| `cmtc-a-global-local` | 417 | 0 | - |
| `cmtc-a-global-remote` | 413 | 23 | 16:26:13.784-16:26:19.823 (7, 28/000,56/000) |
| `cmtc-a-name` | 417 | 0 | - |
| `cmtc-a-same` | 418 | 0 | - |
| `cmtc-b-crosscluster` | 418 | 20 | 16:26:15.765-16:26:34.833 (20, 52/000,56/000) |
| `cmtc-b-crossnode` | 416 | 39 | 16:25:54.674-16:26:34.904 (39, 28/000,52/000,56/000) |
| `cmtc-b-denied` | 210 | 0 | - |
| `cmtc-b-global-local` | 413 | 25 | 16:26:14.804-16:26:34.899 (19, 28/000,56/000) |
| `cmtc-b-global-remote` | 415 | 18 | 16:26:15.821-16:26:34.902 (18, 28/000,56/000) |
| `cmtc-b-name` | 413 | 37 | 16:25:54.691-16:26:34.931 (37, 28/000,56/000) |
| `cmtc-b-same` | 418 | 20 | 16:26:15.760-16:26:34.837 (20, 52/000,56/000) |

| Agent / ztunnel | withdrawn | projected | refreshed in place | restarts |
|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4` | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-lbs8j` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-mpmvz` | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| 0 failed allowed probes | FAIL |
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| every ztunnel renewed its workload certificates | pass |
| no withdrawal on any agent | pass |

### R1-cmtc-b: R1 on cmtc-b, 16:39:03Z, window 150 s

Event: ztunnel-origin-reader exit 0 16:39:24Z. Allowed probes: 1794, failed 0; denied probes: 150, answered 0.

| Path | Requests | Failures | Longest run |
|---|---|---|---|
| `cmtc-a-crosscluster` | 150 | 0 | - |
| `cmtc-a-crossnode` | 150 | 0 | - |
| `cmtc-a-denied` | 75 | 0 | - |
| `cmtc-a-global-local` | 149 | 0 | - |
| `cmtc-a-global-remote` | 149 | 0 | - |
| `cmtc-a-name` | 149 | 0 | - |
| `cmtc-a-same` | 150 | 0 | - |
| `cmtc-b-crosscluster` | 150 | 0 | - |
| `cmtc-b-crossnode` | 150 | 0 | - |
| `cmtc-b-denied` | 75 | 0 | - |
| `cmtc-b-global-local` | 149 | 0 | - |
| `cmtc-b-global-remote` | 149 | 0 | - |
| `cmtc-b-name` | 149 | 0 | - |
| `cmtc-b-same` | 150 | 0 | - |

| Agent / ztunnel | withdrawn | projected | refreshed in place | restarts |
|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4` | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7` | 0 | 0 | 1 | 0 |
| `cmtc-b/cilium-sg2wm` | 0 | 0 | 1 | 0 |

| Verdict | Result |
|---|---|
| 0 failed allowed probes | pass |
| certificates renewed | pass |
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| no withdrawal on any agent | pass |

### R2-cmtc-b: R2 on cmtc-b, 16:41:59Z, window 150 s

Event: ztunnel-membership-writer exit 0 16:42:20Z. Allowed probes: 1791, failed 0; denied probes: 150, answered 0.

| Path | Requests | Failures | Longest run |
|---|---|---|---|
| `cmtc-a-crosscluster` | 149 | 0 | - |
| `cmtc-a-crossnode` | 149 | 0 | - |
| `cmtc-a-denied` | 75 | 0 | - |
| `cmtc-a-global-local` | 149 | 0 | - |
| `cmtc-a-global-remote` | 149 | 0 | - |
| `cmtc-a-name` | 149 | 0 | - |
| `cmtc-a-same` | 150 | 0 | - |
| `cmtc-b-crosscluster` | 149 | 0 | - |
| `cmtc-b-crossnode` | 150 | 0 | - |
| `cmtc-b-denied` | 75 | 0 | - |
| `cmtc-b-global-local` | 149 | 0 | - |
| `cmtc-b-global-remote` | 149 | 0 | - |
| `cmtc-b-name` | 149 | 0 | - |
| `cmtc-b-same` | 150 | 0 | - |

| Agent / ztunnel | withdrawn | projected | refreshed in place | restarts |
|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4` | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm` | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| 0 failed allowed probes | pass |
| certificates renewed | pass |
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| no withdrawal on any agent | pass |

### R3-cmtc-b: R3 on cmtc-b, 16:44:59Z, window 150 s

Event: cmtc-ztunnel-ads-server exit 0 16:45:21Z. Allowed probes: 1794, failed 0; denied probes: 150, answered 0.

| Path | Requests | Failures | Longest run |
|---|---|---|---|
| `cmtc-a-crosscluster` | 150 | 0 | - |
| `cmtc-a-crossnode` | 150 | 0 | - |
| `cmtc-a-denied` | 75 | 0 | - |
| `cmtc-a-global-local` | 149 | 0 | - |
| `cmtc-a-global-remote` | 149 | 0 | - |
| `cmtc-a-name` | 149 | 0 | - |
| `cmtc-a-same` | 150 | 0 | - |
| `cmtc-b-crosscluster` | 150 | 0 | - |
| `cmtc-b-crossnode` | 150 | 0 | - |
| `cmtc-b-denied` | 75 | 0 | - |
| `cmtc-b-global-local` | 149 | 0 | - |
| `cmtc-b-global-remote` | 149 | 0 | - |
| `cmtc-b-name` | 149 | 0 | - |
| `cmtc-b-same` | 150 | 0 | - |

| Agent / ztunnel | withdrawn | projected | refreshed in place | restarts |
|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4` | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm` | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| 0 failed allowed probes | pass |
| certificates renewed | pass |
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| no withdrawal on any agent | pass |

### R4-cmtc-b: R4 on cmtc-b, 16:48:05Z, window 150 s

Event: clustermesh-apiserver-admin-cert exit 0 16:48:26Z, clustermesh-apiserver-local-cert exit 0 16:48:36Z, clustermesh-apiserver-remote-cert exit 0 16:48:46Z, clustermesh-apiserver-server-cert exit 0 16:48:56Z. Allowed probes: 1788, failed 0; denied probes: 150, answered 0.

| Path | Requests | Failures | Longest run |
|---|---|---|---|
| `cmtc-a-crosscluster` | 149 | 0 | - |
| `cmtc-a-crossnode` | 149 | 0 | - |
| `cmtc-a-denied` | 75 | 0 | - |
| `cmtc-a-global-local` | 149 | 0 | - |
| `cmtc-a-global-remote` | 149 | 0 | - |
| `cmtc-a-name` | 149 | 0 | - |
| `cmtc-a-same` | 149 | 0 | - |
| `cmtc-b-crosscluster` | 149 | 0 | - |
| `cmtc-b-crossnode` | 149 | 0 | - |
| `cmtc-b-denied` | 75 | 0 | - |
| `cmtc-b-global-local` | 149 | 0 | - |
| `cmtc-b-global-remote` | 149 | 0 | - |
| `cmtc-b-name` | 149 | 0 | - |
| `cmtc-b-same` | 149 | 0 | - |

| Agent / ztunnel | withdrawn | projected | refreshed in place | restarts |
|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4` | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7` | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm` | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| 0 failed allowed probes | pass |
| certificates renewed | pass |
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| no withdrawal on any agent | pass |

