# Rotation drill R1 on cmtc-a, 2026-11-07T03:05:23Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 03:05:44.024Z to 03:05:44.548Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 150 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 150 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 150 | 0 | - | - |
| `cmtc-a-global-local` | allow | 150 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 149 | 0 | - | - |
| `cmtc-a-name` | allow | 150 | 0 | - | - |
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
| `cmtc-a/cilium-b9cc6/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/cilium-jk7jl/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/ztunnel-cilium-4gbdb/istio-proxy` | 13 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-lbchw/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-q6l85/istio-proxy` | 7 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-vbt5v/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | pass |
| no withdrawal on any agent | pass |
