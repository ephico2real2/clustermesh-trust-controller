# Rotation drill R6 on cmtc-a, 2026-10-28T17:22:39Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 17:22:46.973Z to 17:22:46.973Z. Probe window: 420 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 418 | 56 | 17:22:42.067Z-17:23:38.031Z (56) | 52/000, 56/000 |
| `cmtc-a-crossnode` | allow | 418 | 56 | 17:22:42.050Z-17:23:38.031Z (56) | 52/000, 56/000 |
| `cmtc-a-crosscluster` | allow | 418 | 56 | 17:22:42.104Z-17:23:38.031Z (56) | 52/000, 56/000 |
| `cmtc-a-global-local` | allow | 417 | 56 | 17:22:42.098Z-17:23:38.435Z (56) | 28/000, 52/000, 56/000 |
| `cmtc-a-global-remote` | allow | 417 | 56 | 17:22:42.098Z-17:23:38.421Z (56) | 28/000, 52/000, 56/000 |
| `cmtc-a-name` | allow | 417 | 56 | 17:22:42.108Z-17:23:38.434Z (56) | 28/000, 52/000, 56/000 |
| `cmtc-a-denied` | deny | 212 | 0 | - | - |
| `cmtc-b-same` | allow | 419 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 419 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 419 | 57 | 17:22:42.090Z-17:23:38.322Z (57) | 52/000, 56/000 |
| `cmtc-b-global-local` | allow | 418 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 418 | 52 | 17:22:42.110Z-17:23:31.413Z (50) | 52/000, 56/000 |
| `cmtc-b-name` | allow | 418 | 0 | - | - |
| `cmtc-b-denied` | deny | 210 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-zm4m4/cilium-agent` | 5 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-znm4z/cilium-agent` | 5 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 54 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 20 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-nhfk7/cilium-agent` | 1 | 0 | 1 | 0 | 0 |
| `cmtc-b/cilium-sg2wm/cilium-agent` | 1 | 0 | 1 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 20 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 1 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
| every ztunnel renewed its workload certificates | pass |
