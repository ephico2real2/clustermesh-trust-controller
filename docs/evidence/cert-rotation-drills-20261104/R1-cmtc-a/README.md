# Rotation drill R1 on cmtc-a, 2026-11-04T08:43:33Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 08:43:54.458Z to 08:43:54.597Z. Probe window: 150 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 149 | 149 | 08:43:34.547Z-08:46:03.131Z (149) | 52/000, 56/000 |
| `cmtc-a-crossnode` | allow | 149 | 149 | 08:43:34.580Z-08:46:03.153Z (149) | 52/000, 56/000 |
| `cmtc-a-crosscluster` | allow | 149 | 149 | 08:43:34.596Z-08:46:03.197Z (149) | 52/000, 56/000 |
| `cmtc-a-global-local` | allow | 149 | 149 | 08:43:34.566Z-08:46:03.425Z (149) | 52/000, 56/000 |
| `cmtc-a-global-remote` | allow | 149 | 149 | 08:43:34.597Z-08:46:03.475Z (149) | 52/000, 56/000 |
| `cmtc-a-name` | allow | 149 | 149 | 08:43:34.585Z-08:46:03.475Z (149) | 52/000, 56/000 |
| `cmtc-a-denied` | deny | 75 | 0 | - | - |
| `cmtc-b-same` | allow | 149 | 149 | 08:43:34.613Z-08:46:03.193Z (149) | 52/000, 56/000 |
| `cmtc-b-crossnode` | allow | 149 | 149 | 08:43:34.598Z-08:46:03.193Z (149) | 52/000, 56/000 |
| `cmtc-b-crosscluster` | allow | 149 | 149 | 08:43:34.563Z-08:46:03.134Z (149) | 52/000, 56/000 |
| `cmtc-b-global-local` | allow | 149 | 149 | 08:43:34.614Z-08:46:03.467Z (149) | 52/000, 56/000 |
| `cmtc-b-global-remote` | allow | 149 | 149 | 08:43:34.614Z-08:46:03.471Z (149) | 52/000, 56/000 |
| `cmtc-b-name` | allow | 149 | 149 | 08:43:34.603Z-08:46:03.464Z (149) | 52/000, 56/000 |
| `cmtc-b-denied` | deny | 75 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-b9cc6/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/cilium-jk7jl/cilium-agent` | 1 | 0 | 0 | 1 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 0 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | FAIL |
| no withdrawal on any agent | pass |
