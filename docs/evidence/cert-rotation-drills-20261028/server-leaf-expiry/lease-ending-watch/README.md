# Rotation drill R6 on cmtc-a, 2026-10-28T17:56:33Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 17:56:40.544Z to 17:56:40.545Z. Probe window: 480 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 478 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 478 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 477 | 0 | - | - |
| `cmtc-a-global-local` | allow | 477 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 477 | 0 | - | - |
| `cmtc-a-name` | allow | 477 | 0 | - | - |
| `cmtc-a-denied` | deny | 240 | 0 | - | - |
| `cmtc-b-same` | allow | 478 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 477 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 477 | 0 | - | - |
| `cmtc-b-global-local` | allow | 477 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 477 | 0 | - | - |
| `cmtc-b-name` | allow | 477 | 0 | - | - |
| `cmtc-b-denied` | deny | 240 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-hwvkz/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/cilium-zhxjf/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 21 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 21 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| 0 failed allowed probes | pass |
| no withdrawal on any agent | pass |
| every ztunnel renewed its workload certificates | pass |
