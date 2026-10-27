# Hubble on the CMTC labs, 2026-10-27

Result: Hubble runs on every agent of kind-cmtc-a and kind-cmtc-b with TLS from the mesh PKI, and one Hubble Relay (with
the UI) in cmtc-a observes all four nodes of both clusters. Workload mTLS is unchanged.

| Step | Time (UTC) | Result |
|---|---|---|
| Relay image | 16:40-16:48 | Fork CI run [40543251450](https://github.com/ephico2real2/cilium/actions/runs/40543251450) (`b1c3622a9a`): only `hubble-relay` built, `sha256:bbda6e67…b0413`, amd64 and arm64, version `1.21.0-dev 823d30c5`; the agent tag still resolves to `c77bdc52…` |
| cmtc-a upgrade | 16:53:43-16:54:28 | `cilium_adopt.py plan`: 34 changes, 0 deletions, 0 refusals; `transfer` (backup `/private/tmp/cmtc-opus-final-20261025/review/hubble-cmtc-a-20261027T1653Z/`); `upgrade`: revision 8 |
| cmtc-b upgrade | 16:55:37-16:56:10 | plan: 20 changes, 0 refusals; `upgrade`: revision 8 (after the Helm adoption, [helm-adoption-cmtc-b-20261027](../helm-adoption-cmtc-b-20261027/README.md)) |
| Certificates | | `hubble-server-certs` (both), `hubble-relay-client-certs`, `hubble-relay-server-certs`, `hubble-ui-client-certs` (cmtc-a): Ready, each CertificateRequest `Approved` by `cert-manager.io`, issued by `<cluster>-clustermesh-intermediate` |
| Restarts | | Agents one at a time on each cluster; ztunnel Pods not replaced (6 h), clustermesh-apiserver not restarted (23 h) |
| Drift | | `cilium_release.py check --strict`: 0 differences on both clusters |
| Relay | 16:56 | `hubble list nodes` through the Relay over TLS (`--tls-ca-cert-files` = `cmtc-public-root`, server name `relay.hubble-relay.cilium.io`): 4/4 Connected ([list-nodes.txt](list-nodes.txt)). The Relay verified cmtc-b's agents, signed by `cmtc-b-clustermesh-intermediate`, against the mesh root alone |
| mTLS matrix | 16:57 | [matrix/join.txt](matrix/join.txt): 96 proven over mTLS, 36 dropped by Cilium, 0 failed |
| Flows | 16:58 | [observe-cmtc-live-mtls.txt](observe-cmtc-live-mtls.txt): enrolled probes show as workload-to-workload TCP to port 15008 (HBONE), `FORWARDED`; unregistered callers show `Policy denied DROPPED` |
| Metrics | 17:05 | Prometheus targets up: cmtc-a `hubble` 2, `hubble-relay` 1; cmtc-b `hubble` 2. The hub holds 8 `hubble_*_total` families for each cluster (cmtc-b by remote write) and `hubble_relay_pool_peer_connection_status` |

Found and fixed during the rollout:

- The lab Prometheus had run the configuration of 2026-10-24 since then: `scripts/lab/monitoring.sh` updated the
  ConfigMap, and Prometheus reads it only at start, so the `ztunnel` job and later scrape changes never took effect.
  `scripts/lab/monitoring.py` now puts the configuration's SHA-256 on the Pod template, so an apply restarts
  Prometheus when its configuration changes.
- `scripts/lab/up.sh` ran `cilium_cluster_values.py` with `python3`, which has no PyYAML on macOS; it now uses the
  repository venv when present.

Not measured: Hubble's view of a cross-cluster HBONE connection (the capture shows the flows on each node, not one
flow joined across clusters), and three cmtc-b `FORWARDED` flows to plain ports 80, 8080 and 31337 in the 15-minute
window, which are not explained yet.
