# Rotation drill R6 on cmtc-a, 2026-10-28T19:04:02Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 19:04:10.057Z to 19:04:10.057Z. Probe window: 420 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 419 | 20 | 19:04:20.239Z-19:04:39.315Z (20) | 52/000, 56/000 |
| `cmtc-a-crossnode` | allow | 415 | 37 | 19:04:20.243Z-19:04:58.404Z (37) | 28/000, 52/000, 56/000 |
| `cmtc-a-crosscluster` | allow | 418 | 20 | 19:04:20.279Z-19:04:39.349Z (20) | 56/000 |
| `cmtc-a-global-local` | allow | 414 | 28 | 19:04:20.318Z-19:04:40.422Z (20) | 28/000, 56/000 |
| `cmtc-a-global-remote` | allow | 417 | 19 | 19:04:20.329Z-19:04:39.437Z (19) | 28/000, 52/000, 56/000 |
| `cmtc-a-name` | allow | 414 | 36 | 19:04:20.323Z-19:04:58.518Z (36) | 28/000, 52/000, 56/000 |
| `cmtc-a-denied` | deny | 210 | 0 | - | - |
| `cmtc-b-same` | allow | 419 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 418 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 416 | 20 | 19:04:20.313Z-19:04:40.394Z (19) | 28/000, 56/000 |
| `cmtc-b-global-local` | allow | 418 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 415 | 19 | 19:04:41.441Z-19:04:45.465Z (5) | 56/000 |
| `cmtc-b-name` | allow | 418 | 0 | - | - |
| `cmtc-b-denied` | deny | 210 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-hwvkz/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-zhxjf/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 101 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 79 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 21 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
| every ztunnel renewed its workload certificates | pass |
