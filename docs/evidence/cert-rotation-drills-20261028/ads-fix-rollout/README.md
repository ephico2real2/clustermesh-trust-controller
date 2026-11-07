# The ztunnel ADS certificate reload, deployed and drilled on both clusters, 2026-10-28 (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Result: with Cilium fork `c84f7d0741` on both clusters, the Cilium agent serves a renewed ztunnel ADS server
certificate to new TLS handshakes without a restart. A renewal under traffic (R3) reached every node in 11 to 58 s,
with 0 failed probes on both clusters. The agent upgrades themselves had the known restart gap (about 40 s per
cluster). The SPIRE X.509 CA activations of both clusters ran inside the cmtc-b upgrade's probe window, with 0
failures after the restart gap.

State: **deployed and traffic-qualified** on kind-cmtc-a and kind-cmtc-b (this run). It closes the defect found in
the [server leaf expiry test](../server-leaf-expiry/README.md#the-outage-on-kind-cmtc-a-171155z-to-172347z).

## The fix

- Before: `pkg/ztunnel/xds/xds_server.go` `Serve()` loaded the pair once, through
  `credentials.NewServerTLSFromFile` (`pkg/ztunnel/ca/ca_server.go:77` at `ce5c3ec031`).
- Now: `ca.LoadServerTLSCredentials` builds the gRPC credentials on `certloader.NewWatchedServerConfig`. It polls
  the mounted files every 5 s and gives each new handshake the pair on disk. A pair that fails to load is logged
  (`Keypair update failed`) and the last good pair stays in service. Established streams are not touched.
- Image: `ghcr.io/ephico2real2/cilium-dev@sha256:369090126600…dafa60` (CI run 40738186605, head `c84f7d0741`), agent
  only. The operator and the clustermesh-apiserver keep their images.
- Independent review (OB1-lite, read-only, eight claims): SHIP, no change asked. It measured the fork's tests under
  `-race` and confirmed that the new tests fail on the old code. It noted one limit that is not a regression: a client
  that resumes a TLS session from before a renewal is shown no certificate, as before.

## Steps

| Time (UTC) | Step | Record |
|---|---|---|
| 18:11Z | `config/cilium-images.lock.json` `images.agent` set to the digest above. `cilium_release.py check --strict`: 7 differences per cluster, all the agent image. `cilium_adopt.py plan`: 8 changes, 0 deletions, 0 refusals per cluster | |
| 18:50:44Z to 18:51:11Z | cmtc-b `cilium_adopt.py upgrade` (Helm revision 13) under the R6 watch. Both agents log `Cilium 1.21.0-dev c84f7d07` | [upgrade-ads-cmtc-b](../upgrade-ads-cmtc-b/README.md) |
| 18:52:46Z, 18:54:21Z | SPIRE `X509 CA activated` on cmtc-b, then cmtc-a (SPIRE server logs), inside the cmtc-b watch | [SPIRE CA activation](#the-spire-ca-activations) |
| 18:58:00Z to 19:02:05Z | Matrix on both clusters | [matrix-1858](../../cert-renewal-20261028/matrix-1858/join.txt) |
| 19:04:10Z to 19:04:41Z | cmtc-a upgrade (Helm revision 12) under the R6 watch | [upgrade-ads-cmtc-a](../upgrade-ads-cmtc-a/README.md) |
| 19:12:27Z | R3 on cmtc-b: `cmctl renew cmtc-ztunnel-ads-server`, revision 5 to 6 | [R3-ads-reload-cmtc-b](../R3-ads-reload-cmtc-b/README.md) |
| 19:18:01Z | R3 on cmtc-a: revision 4 to 5 | [R3-ads-reload-cmtc-a](../R3-ads-reload-cmtc-a/README.md) |
| 19:23Z | `cilium_release.py check --strict`: 0 differences on both clusters. Neither clustermesh-apiserver Pod restarted | |

## The upgrades

Before the upgrade, each cmtc-b node served ADS revision 4 (NotAfter 2026-10-29T11:17:16Z) while the Certificate was
at revision 5. After it, both served revision 5. On cmtc-a the Certificate was still at revision 4, so the served
certificate did not change.

| Watch | Allowed probes | Failed | When | Denied probes answered | Withdrawals |
|---|---|---|---|---|---|
| cmtc-b, 18:50:38Z to 18:57:39Z | 4,985 | 200 | 18:50:51Z to 18:51:31Z | 0 of 420 | 0 |
| cmtc-a, 19:04:05Z to 19:11:06Z | 5,001 | 199 | 198 from 19:04:19Z to 19:04:58Z; 1 at 19:06:59.033Z | 0 of 420 | 0 |
| For comparison: cmtc-b to `ce5c3ec031`, 16:25:39Z | 4,991 | 199 | 16:25:54Z to 16:26:35Z | 0 of 420 | 0 |

- The failures fall in the two agent restarts of each cluster. When an agent stops, its ztunnel loses the xDS
  stream to `localhost:15012`, ends its HBONE streams (fail closed) and retries until the new agent serves: 10 failed
  reconnects per ztunnel, 0 `certificate expired` lines. This is the restart gap of every agent rollout (#47 P10), not
  a change of this fix.
- The cmtc-a failure at 19:06:59.033Z: the cmtc-b worker ztunnel used a pooled HBONE connection to cmtc-a's
  `server-worker` after cmtc-a's restart, and refused it with `h2 failed: authenticated issuer profile/session
  expired or changed`, `bytes_sent=0`. ztunnel ends a pooled connection whose issuer profile session changed (fail
  closed); the next probe passed. Open: a request that sent no bytes could be retried on a new connection.
- The cmtc-b control-plane agent logged `Rejecting incomplete strict workload Address snapshot` once at 18:51:20Z
  (`native Kubernetes node discovery has not synchronized`) and sent its initial snapshot at 18:51:25Z.
- The watch follows the agent Pods that the upgrade replaces, so its agent counts are 0. The build and the served
  certificate were read from the new Pods.

## The R3 drills: a renewal reaches new handshakes without a restart

The drill now also does a TLS handshake to `127.0.0.1:15012` in each kind node every 5 s (`openssl s_client`, the
served certificate only) until every node serves the renewed certificate. Before the event it requires each node to
serve the current revision. That check refuses to start on a cluster with the old defect: at 18:12Z it reported
revision 4 against revision 5 on both cmtc-b nodes.

| Cluster | Renewed | Node | Agent `Keypair updated` | New handshake serves it |
|---|---|---|---|---|
| cmtc-b | 19:12:27Z, revision 6, serial `58E58329…` | control-plane (`cilium-p9lgb`) | 19:12:35.08Z | 19:12:37.8Z |
| | | worker (`cilium-zlj26`) | 19:13:03.22Z | 19:13:03.7Z |
| cmtc-a | 19:18:01Z, revision 5, serial `20D48A46…` | worker (`cilium-jk7jl`) | 19:18:22.85Z | 19:18:27.6Z |
| | | control-plane (`cilium-b9cc6`) | 19:18:55.20Z | 19:18:58.6Z |

The time from renewal to `Keypair updated` (8 to 54 s) is mostly the kubelet's Secret volume sync; the agent polls
every 5 s. Each drill: 3,582 allowed probes, 0 failed; 300 denied probes, 0 answered; 0 withdrawals; every verdict
passed. The ADS certificates now expire 2026-10-29T19:12:27Z (cmtc-b) and 19:18:01Z (cmtc-a), and the agents load
each renewal from now on.

## The SPIRE CA activations

| Cluster | Activated | New CA (`local_authority_id`) | Expires | Old CA retained to |
|---|---|---|---|---|
| cmtc-b | 18:52:46Z | `15f0fca6…` | 2026-10-29 10:52:46Z | 22:52:43Z |
| cmtc-a | 18:54:21Z | `2568bb4f…` | 2026-10-29 10:54:21Z | 22:54:12Z |

- Records: SPIRE server logs (`X509 CA activated`); [spire-authorities-1858.json](../../cert-renewal-20261028/spire-authorities-1858.json)
  (`local_authority.py show`: each prepared CA of 13:53Z is now active, no CA prepared).
- At 18:58Z every workload leaf in the ztunnel config dumps of the four nodes was issued between 18:56:56Z and
  18:57:33Z, with the new CA's key as its authority key identifier. So the leaves moved to the new CAs inside the
  cmtc-b watch, which had 0 failures from 18:51:31Z to its end at 18:57:39Z.
- [matrix-1858](../../cert-renewal-20261028/matrix-1858/join.txt), 18:58:00Z to 19:02:05Z: every allowed probe returned
  HTTP 200 (`trafficChecksPassed` equals `selected` in every scope); 93 joined to a ztunnel mTLS line; 36 unregistered probes dropped
  by Cilium. The join reports 3 failed: ztunnel logged those connections with a source port that differs from the
  one curl reported (the case recorded in [approval-arbiter-20261027](../../approval-arbiter-20261027/README.md)). The
  matching mTLS lines, same client, destination and time:

  | Probe | curl's socket | ztunnel line | Client identity |
  |---|---|---|---|
  | cmtc-a to `10.20.1.116:8080` | `10.10.1.205:52538` | `10.10.1.205:30129`, 18:58:05.783Z | `spiffe://cmtc-a.mesh.example/ns/cmtc-live-mtls/sa/mesh-client` |
  | cmtc-b to `10.10.0.98:8080` | `10.20.1.242:51620` | `10.20.1.242:11341`, 18:59:05.386Z | `spiffe://cmtc-b.mesh.example/ns/cmtc-live-mtls/sa/mesh-client` |
  | cmtc-b to `server-cmtc-b…:31337` | `10.20.1.242:54510` | `10.20.1.242:53289` to `10.20.0.92:31337`, 18:59:06.428Z | `spiffe://cmtc-b.mesh.example/ns/cmtc-live-mtls/sa/mesh-client` |

- Limit: the activation was not a drill of its own. The same probe window also holds the cmtc-b restart gap, which
  ended 75 s before the first activation.

## Open

- The agent restart gap of about 40 s per cluster (#47 P10).
- A pooled HBONE request refused after a peer's issuer session changed, with 0 bytes sent (1 probe at 19:06:59Z).
- The rotation drill does not follow agent Pods that an upgrade replaces.
