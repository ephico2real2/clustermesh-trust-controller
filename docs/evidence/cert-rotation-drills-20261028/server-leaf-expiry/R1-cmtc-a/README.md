# Rotation drill R1 on cmtc-a, 2026-10-28T17:11:00Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 17:11:21.379Z to 17:11:21.602Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 149 | 95 | 17:11:55.773Z-17:13:30.115Z (95) | 52/000, 56/000 |
| `cmtc-a-crossnode` | allow | 149 | 95 | 17:11:55.775Z-17:13:30.115Z (95) | 52/000, 56/000 |
| `cmtc-a-crosscluster` | allow | 149 | 95 | 17:11:55.785Z-17:13:30.115Z (95) | 52/000, 56/000 |
| `cmtc-a-global-local` | allow | 149 | 95 | 17:11:55.906Z-17:13:30.406Z (95) | 52/000, 56/000 |
| `cmtc-a-global-remote` | allow | 149 | 95 | 17:11:55.906Z-17:13:30.406Z (95) | 52/000, 56/000 |
| `cmtc-a-name` | allow | 149 | 95 | 17:11:55.923Z-17:13:30.406Z (95) | 52/000, 56/000 |
| `cmtc-a-denied` | deny | 75 | 0 | - | - |
| `cmtc-b-same` | allow | 149 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 149 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 149 | 95 | 17:11:55.837Z-17:13:30.272Z (95) | 56/000 |
| `cmtc-b-global-local` | allow | 149 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 149 | 90 | 17:12:04.985Z-17:13:30.515Z (86) | 56/000 |
| `cmtc-b-name` | allow | 149 | 0 | - | - |
| `cmtc-b-denied` | deny | 75 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4/cilium-agent` | 12 | 1 | 0 | 0 | 1 |
| `cmtc-a/cilium-znm4z/cilium-agent` | 11 | 1 | 0 | 0 | 1 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 120 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 109 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 6 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | FAIL |
