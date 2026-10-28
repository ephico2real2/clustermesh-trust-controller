# Rotation drill R1 on cmtc-b, 2026-10-28T17:13:35Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 17:13:55.978Z to 17:13:56.175Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 150 | 150 | 17:13:36.119Z-17:16:05.657Z (150) | 52/000, 56/000 |
| `cmtc-a-crossnode` | allow | 150 | 150 | 17:13:36.109Z-17:16:05.657Z (150) | 52/000, 56/000 |
| `cmtc-a-crosscluster` | allow | 150 | 150 | 17:13:36.124Z-17:16:05.657Z (150) | 52/000, 56/000 |
| `cmtc-a-global-local` | allow | 150 | 150 | 17:13:36.135Z-17:16:05.920Z (150) | 52/000, 56/000 |
| `cmtc-a-global-remote` | allow | 150 | 150 | 17:13:36.148Z-17:16:05.966Z (150) | 52/000, 56/000 |
| `cmtc-a-name` | allow | 150 | 150 | 17:13:36.133Z-17:16:05.920Z (150) | 52/000, 56/000 |
| `cmtc-a-denied` | deny | 75 | 0 | - | - |
| `cmtc-b-same` | allow | 150 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 150 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 150 | 150 | 17:13:36.183Z-17:16:05.871Z (150) | 52/000, 56/000 |
| `cmtc-b-global-local` | allow | 149 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 149 | 149 | 17:13:36.179Z-17:16:05.106Z (149) | 52/000, 56/000 |
| `cmtc-b-name` | allow | 149 | 0 | - | - |
| `cmtc-b-denied` | deny | 75 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 70 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 70 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 4 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
