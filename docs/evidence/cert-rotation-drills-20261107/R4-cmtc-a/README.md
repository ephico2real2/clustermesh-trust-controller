# Rotation drill R4 on cmtc-a, 2026-11-07T03:10:33Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 03:10:53.928Z to 03:11:24.975Z. Probe window: 200 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 199 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 199 | 1 | 03:13:04.038Z-03:13:04.038Z (1) | 56/000 |
| `cmtc-a-crosscluster` | allow | 199 | 0 | - | - |
| `cmtc-a-global-local` | allow | 199 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 199 | 0 | - | - |
| `cmtc-a-name` | allow | 199 | 0 | - | - |
| `cmtc-a-denied` | deny | 100 | 0 | - | - |
| `cmtc-b-same` | allow | 199 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 199 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 199 | 0 | - | - |
| `cmtc-b-global-local` | allow | 199 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 199 | 0 | - | - |
| `cmtc-b-name` | allow | 199 | 0 | - | - |
| `cmtc-b-denied` | deny | 100 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-b9cc6/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-jk7jl/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-4gbdb/istio-proxy` | 11 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-lbchw/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-q6l85/istio-proxy` | 10 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-vbt5v/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
