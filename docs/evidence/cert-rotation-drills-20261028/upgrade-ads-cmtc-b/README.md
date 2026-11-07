# Rotation drill R6 on cmtc-b, 2026-10-28T18:50:36Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 18:50:43.535Z to 18:50:43.535Z. Probe window: 420 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 418 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 418 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 415 | 18 | 18:50:51.760Z-18:51:10.839Z (18) | 28/000, 52/000, 56/000 |
| `cmtc-a-global-local` | allow | 417 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 412 | 21 | 18:50:51.792Z-18:50:57.848Z (7) | 56/000 |
| `cmtc-a-name` | allow | 417 | 0 | - | - |
| `cmtc-a-denied` | deny | 210 | 0 | - | - |
| `cmtc-b-same` | allow | 418 | 21 | 18:50:51.763Z-18:51:11.841Z (21) | 52/000, 56/000 |
| `cmtc-b-crossnode` | allow | 414 | 36 | 18:50:51.774Z-18:51:30.944Z (36) | 28/000, 52/000, 56/000 |
| `cmtc-b-crosscluster` | allow | 418 | 21 | 18:50:51.761Z-18:51:11.844Z (21) | 56/000 |
| `cmtc-b-global-local` | allow | 412 | 30 | 18:50:51.805Z-18:51:16.958Z (24) | 28/000, 52/000, 56/000 |
| `cmtc-b-global-remote` | allow | 415 | 19 | 18:50:51.810Z-18:51:11.934Z (19) | 28/000, 52/000, 56/000 |
| `cmtc-b-name` | allow | 411 | 34 | 18:50:51.805Z-18:51:31.034Z (34) | 28/000, 52/000, 56/000 |
| `cmtc-b-denied` | deny | 210 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-hwvkz/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-zhxjf/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 27 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 1 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 103 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 80 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
| every ztunnel renewed its workload certificates | pass |
