# Rotation drill R2 on cmtc-a, 2026-11-07T03:07:58Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 03:08:18.994Z to 03:08:19.138Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 150 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 150 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 150 | 0 | - | - |
| `cmtc-a-global-local` | allow | 149 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 149 | 0 | - | - |
| `cmtc-a-name` | allow | 149 | 0 | - | - |
| `cmtc-a-denied` | deny | 75 | 0 | - | - |
| `cmtc-b-same` | allow | 150 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 150 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 150 | 0 | - | - |
| `cmtc-b-global-local` | allow | 149 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 149 | 0 | - | - |
| `cmtc-b-name` | allow | 149 | 0 | - | - |
| `cmtc-b-denied` | deny | 75 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-b9cc6/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-jk7jl/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-4gbdb/istio-proxy` | 5 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-lbchw/istio-proxy` | 1 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-q6l85/istio-proxy` | 9 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-vbt5v/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | pass |
| no withdrawal on any agent | pass |
