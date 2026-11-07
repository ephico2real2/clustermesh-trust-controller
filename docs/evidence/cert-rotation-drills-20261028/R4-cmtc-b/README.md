# Rotation drill R4 on cmtc-b, 2026-10-28T16:48:05Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 16:48:26.501Z to 16:48:56.792Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 149 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 149 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 149 | 0 | - | - |
| `cmtc-a-global-local` | allow | 149 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 149 | 0 | - | - |
| `cmtc-a-name` | allow | 149 | 0 | - | - |
| `cmtc-a-denied` | deny | 75 | 0 | - | - |
| `cmtc-b-same` | allow | 149 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 149 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 149 | 0 | - | - |
| `cmtc-b-global-local` | allow | 149 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 149 | 0 | - | - |
| `cmtc-b-name` | allow | 149 | 0 | - | - |
| `cmtc-b-denied` | deny | 75 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 12 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 1 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 8 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | pass |
| no withdrawal on any agent | pass |
