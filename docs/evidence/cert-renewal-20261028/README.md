# Certificate renewals on kind-cmtc-a and kind-cmtc-b, 2026-10-28

Result: every certificate that reached its renewal time between 07:35Z and 13:53Z renewed, and each one is Ready.
After the ClusterMesh renewals at 13:47-13:51Z, ClusterMesh is 1/1 ready on both clusters, and the
clustermesh-apiservers have 0 restarts. The mTLS matrix that ran across those renewals proved all 96 allowed probes
over mTLS. When the ztunnel origin client certificates renewed at 11:47-11:51Z, each Cilium agent withdrew the peer
cluster's workloads for 270 to 311 ms and then projected them again. No traffic test ran in that window.

State: **observed** (current). Nothing was changed on the clusters to make these renewals.

## cert-manager Certificates

[cmtc-a](certificates-cmtc-a-1353.txt), [cmtc-b](certificates-cmtc-b-1353.txt), 13:53Z.

| Certificate (kube-system) | cmtc-a renewed | cmtc-b renewed | Lifetime | New revision |
|---|---|---|---|---|
| `cmtc-ztunnel-ads-server` | 11:17:15Z | 11:17:16Z | 24 h | 4 |
| `ztunnel-membership-writer` | 11:47:44Z | 11:50:46Z | 24 h | 4 |
| `ztunnel-origin-reader` | 11:47:54Z | 11:50:56Z | 24 h | 4 |
| `clustermesh-apiserver-{admin,local,remote}-cert` | 13:47:10-13:47:32Z | 13:50:12-13:50:34Z | 24 h | 7 |
| `clustermesh-apiserver-server-cert` | 13:48:06Z | 13:51:07Z | 24 h | 7 |

The `clustermesh-apiserver-server-cert` key did not change. The new certificate's key hash (SHA-256 of the public
key, from the CertificateRequest status) equals the pin in the peer's `kube-system/ztunnel-origin-config`. On cmtc-a
both are `d1a0d97f…3214`, and on cmtc-b both are `0822f405…8199`. The values file sets `rotationPolicy: Never` for
this key (`config/lab/cilium/base.yaml`). The ClusterMesh certificates live 1 day because the release has
`certValidityDuration: 1`: `base.yaml` sets 365, and its comment says `live-labs.yaml` keeps the two current labs
at 1 day until they move.

## ztunnel origin certificates: the agents reconnect

[agent-origin-reconnect.log](agent-origin-reconnect.log) has the agent lines of 11:47:30-11:52:30Z. When the kubelet
updates the projected certificate files, the agent logs `origin configuration changed` and withdraws the peer's
workloads. It then reconnects to the peer's etcd with the new certificate, lists both prefixes, and projects the
peer again. To deliver the peer, it closes the ztunnel xDS stream and opens a fresh one; that close is the one
`error while receiving request from Delta xDS stream` (`context canceled`).

| Agent | Withdrawn | Projected | Gap |
|---|---|---|---|
| cmtc-a `cilium-znm4z` | 11:48:04.137Z | 11:48:04.407Z | 270 ms |
| cmtc-a `cilium-zm4m4` | 11:48:24.760Z | 11:48:25.071Z | 311 ms |
| cmtc-b `cilium-mpmvz` | 11:51:03.094Z | 11:51:03.405Z | 311 ms |
| cmtc-b `cilium-lbs8j` | 11:51:37.405Z | 11:51:37.715Z | 309 ms |

While the peer is withdrawn, its callers are not admitted as policy sources. A cross-cluster connection that starts
in the gap is denied: the path fails closed. No probe ran in that window, so the effect on traffic is not measured.

## SPIRE workload certificates and CAs

ztunnel config dumps, 13:50Z, all four nodes (public certificates only, 0 `PRIVATE KEY`). Every workload leaf
(`mesh-client` and `rebel-base` on each node) is `Available`, lives 130 s, and is less than 60 s old. The leaves are
signed by the CAs that activated during the outage of 2026-10-28
([spire-sidecar-outage-20261028](../spire-sidecar-outage-20261028/README.md)).

[spire-authorities-1353.json](spire-authorities-1353.json) (`scripts/lab/spire/local_authority.py show`):

| Cluster | Active CA, expires | Prepared CA, expires | Upstream of both (SPIRE intermediate SKI) |
|---|---|---|---|
| cmtc-a | `b393af1b…`, 22:54:12Z | `2568bb4f…`, 2026-10-29 10:54:21Z | `78dee534…` |
| cmtc-b | `93fead96…`, 22:52:43Z | `15f0fca6…`, 2026-10-29 10:52:46Z | `52d271bd…` |

SPIRE activates the prepared CA at five sixths of the active CA's lifetime. The active CAs became valid at 22:54:12Z
(cmtc-a) and 22:52:43Z (cmtc-b) on 2026-10-27 and live 24 h, so the next activations are due at about 18:54Z and
18:53Z. The prepared CAs are signed by the same per-cluster SPIRE intermediates as the active ones.

## Traffic

[matrix-1349](../spire-sidecar-outage-20261028/matrix-1349/join.txt), 13:48:26-13:52:30Z, covers the ClusterMesh
renewals on both clusters: 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed.

## Open

- The 270-311 ms withdrawal at an origin certificate renewal is not measured under traffic. It is the same mechanism
  as [finding 08](../clustermesh-pki-20261026/cutover/08-finding-origin-reader-renewal.md) (0.4 to 10 s of failed
  cross-cluster requests, 2026-10-26); the fix is issue #46.
- The SPIRE agents log `Failed to send X.509 SVID response` (`context canceled`, `DelegatedIdentity`,
  `SubscribeToX509SVIDs`) 2 to 6 times per agent between 07:30Z and 13:48Z. Not investigated.
- Observe the SPIRE CA activations at about 18:53-18:54Z with a matrix after them.
