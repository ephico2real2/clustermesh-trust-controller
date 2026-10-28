# Rotation drill R3 on cmtc-a, 2026-10-28T19:17:39Z

State: **measured** (this run). Files: `summary.json` (everything), `traffic.jsonl` (one row per probe), `plan.json`,
`preflight.json`, `logs/*.events` (the Cilium agent and ztunnel lines that matter, host-stamped) and `logs/*.log` (raw).

Event: 19:18:01.459Z to 19:18:01.614Z. Probe window: 300 s, one probe per second per path.

| Path | Expect | Requests | Failures | Longest failure run | Codes |
|---|---|---|---|---|---|
| `cmtc-a-same` | allow | 299 | 0 | - | - |
| `cmtc-a-crossnode` | allow | 299 | 0 | - | - |
| `cmtc-a-crosscluster` | allow | 299 | 0 | - | - |
| `cmtc-a-global-local` | allow | 298 | 0 | - | - |
| `cmtc-a-global-remote` | allow | 298 | 0 | - | - |
| `cmtc-a-name` | allow | 298 | 0 | - | - |
| `cmtc-a-denied` | deny | 150 | 0 | - | - |
| `cmtc-b-same` | allow | 299 | 0 | - | - |
| `cmtc-b-crossnode` | allow | 299 | 0 | - | - |
| `cmtc-b-crosscluster` | allow | 299 | 0 | - | - |
| `cmtc-b-global-local` | allow | 298 | 0 | - | - |
| `cmtc-b-global-remote` | allow | 298 | 0 | - | - |
| `cmtc-b-name` | allow | 298 | 0 | - | - |
| `cmtc-b-denied` | deny | 150 | 0 | - | - |

| Agent or ztunnel | Lines kept | withdrawn | projected | transport refreshes | restarts |
|---|---|---|---|---|---|
| `cmtc-a/cilium-b9cc6/cilium-agent` | 1 | 0 | 0 | 0 | 0 |
| `cmtc-a/cilium-jk7jl/cilium-agent` | 1 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-5l4kd/istio-proxy` | 16 | 0 | 0 | 0 | 0 |
| `cmtc-a/ztunnel-cilium-fg2qr/istio-proxy` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-p9lgb/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/cilium-zlj26/cilium-agent` | 0 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-rxmwb/istio-proxy` | 20 | 0 | 0 | 0 | 0 |
| `cmtc-b/ztunnel-cilium-w6hrb/istio-proxy` | 1 | 0 | 0 | 0 | 0 |

| Verdict | Result |
|---|---|
| denied paths never answered | pass |
| every path probed for the whole window | pass |
| certificates renewed | pass |
| 0 failed allowed probes | pass |
| no withdrawal on any agent | pass |
| every node presents the renewed ADS certificate to a new handshake | pass |
