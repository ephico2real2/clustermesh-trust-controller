# Rotation drill R6 on cmtc-b, 2026-10-28T16:25:39Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 16:25:47.439Z to 16:25:47.439Z. Probe window: 420 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 418 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 418 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 415 | 17 | 16:26:15.762Z-16:26:33.837Z (17) | 28/000, 56/000 |
| `cmtc-a-global-local` | allow | 417 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 413 | 23 | 16:26:13.784Z-16:26:19.823Z (7) | 28/000, 56/000 |
| `cmtc-a-name` | allow | 417 | 0 | - | - |
| `cmtc-a-denied` | deny | 210 | 0 | - | - |
| `cmtc-b-same` | allow | 418 | 20 | 16:26:15.760Z-16:26:34.837Z (20) | 52/000, 56/000 |
| `cmtc-b-crossnode` | allow | 416 | 39 | 16:25:54.674Z-16:26:34.904Z (39) | 28/000, 52/000, 56/000 |
| `cmtc-b-crosscluster` | allow | 418 | 20 | 16:26:15.765Z-16:26:34.833Z (20) | 52/000, 56/000 |
| `cmtc-b-global-local` | allow | 413 | 25 | 16:26:14.804Z-16:26:34.899Z (19) | 28/000, 56/000 |
| `cmtc-b-global-remote` | allow | 415 | 18 | 16:26:15.821Z-16:26:34.902Z (18) | 28/000, 56/000 |
| `cmtc-b-name` | allow | 413 | 37 | 16:25:54.691Z-16:26:34.931Z (37) | 28/000, 56/000 |
| `cmtc-b-denied` | deny | 210 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 3807 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 1280 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-lbs8j/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-mpmvz/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 3756 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 1246 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
| every ztunnel renewed its workload certificates | pass |
