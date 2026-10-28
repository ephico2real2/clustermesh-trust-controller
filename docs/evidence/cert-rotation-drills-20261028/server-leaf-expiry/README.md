# ClusterMesh server leaf expiry, and the ADS certificate outage on kind-cmtc-a, 2026-10-28 (#47, #46)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../../../agile/DELIVERY_STATUS.md) and [documentation terms](../../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Result: with the origin-session renewal build (Cilium fork `ce5c3ec031`, agent image
`cilium-dev@sha256:8446cf910bdb…69b2cc`) on both clusters, each Cilium agent renewed its direct-origin session in
place 10 minutes before the peer's ClusterMesh server certificate expired: 0 withdrawals, and 0 failed probes out of
5,727 allowed probes on 12 allowed paths. The test also caused a 12-minute mTLS outage on kind-cmtc-a (17:11:55Z to
17:23:47Z), from a separate defect: the agent loaded its ztunnel ADS server certificate once, at start.

State: **measured** (this run). The lease-ending refresh is **traffic-qualified** on both clusters. The ADS defect is
**fixed in the fork and not deployed** (see [Open](#open)).

## Why the test used 1-hour certificates

The operator asked for the expiry path to be tested at once (17:06Z), instead of waiting for the predicted
withdrawals at 21:48Z and 21:51Z. cert-manager refuses a Certificate shorter than 1 hour
(`MinimumCertificateDuration = time.Hour` in `pkg/apis/certmanager/v1/const.go`; the v1.21.1 webhook refused 10m).
cert-manager stays the issuer, so the shortest real leaf is 1 hour.

## Steps

| Time (UTC) | Step | Record |
|---|---|---|
| 17:10:01Z, 17:10:02Z | `clustermesh-apiserver-server-cert` set to `duration: 1h`, `renewBefore: 20m` on cmtc-b and cmtc-a (field manager `cmtc-rotation-drill`). A spec change re-issues at once. New leaves: cmtc-b revision 9, NotAfter 18:10:01Z; cmtc-a revision 8, NotAfter 18:10:02Z. The key was kept (`rotationPolicy: Never`), so the peers' pins did not change | BRIEF |
| 17:11:21Z | R1 on cmtc-a (`cmctl renew ztunnel-origin-reader`). The cmtc-a agents ran the previous build (`823d30c51b`): they withdrew cmtc-b at 17:11:55Z and 17:12:06Z and reconnected, against cmtc-b's 1-hour leaf | [R1-cmtc-a](R1-cmtc-a/README.md) |
| 17:11:55Z | **Outage begins on cmtc-a** (next section) | [outage-cmtc-a](outage-cmtc-a/) |
| 17:13:56Z | R1 on cmtc-b. Both cmtc-b agents (new build): `Direct-origin transport refreshed in place` reason `client credential renewed` at 17:14:35Z and 17:14:51Z, `leaseEnd=2026-10-28T18:10:02.000Z` (cmtc-a's 1-hour leaf) | [R1-cmtc-b](R1-cmtc-b/README.md) |
| 17:21:58Z | cmtc-a's server certificate spec put back to the Helm render (`24h0m0s`, no `renewBefore`): revision 9, 24 h | |
| 17:22:54Z to 17:23:19Z | cmtc-a Cilium upgrade to the new build through Helm (revision 11): `cilium_release.py check --strict` 7 differences, all the agent image; `cilium_adopt.py plan` 8 changes, 0 deletions, 0 refusals. Both agents log `Cilium 1.21.0-dev ce5c3ec0`. Both ztunnels Ready at 17:23:47Z: **outage ends** | [upgrade-cmtc-a](../upgrade-cmtc-a/README.md) |
| 17:24:03Z | cmtc-b's server certificate spec put back (revision 10, 24 h). `spec.duration` ownership moved back into Helm's apply entry and the `cmtc-rotation-drill` entries removed, generation unchanged. `cilium_release.py check --strict`: 0 differences on both clusters | |
| 18:00:02Z to 18:00:04Z | **Lease-ending refresh**, see below | [lease-ending-watch](lease-ending-watch/README.md) |

## The lease-ending refresh

Each agent's session was bound to the peer's 1-hour leaf: the cmtc-a agents (started 17:23Z) to cmtc-b's revision 9
(NotAfter 18:10:01Z), the cmtc-b agents (R1 at 17:14Z) to cmtc-a's revision 8 (NotAfter 18:10:02Z). The agent
renews the session `originRefreshLead` (10 minutes) before that end. By then cert-manager had already written the
24-hour leaves, so the new handshake found them.

| Agent | Refreshed in place | Took | New `leaseEnd` |
|---|---|---|---|
| cmtc-a `cilium-hwvkz` | 18:00:02.585Z, reason `lease ending` | 4.06 ms | 2026-10-29T17:11:21Z |
| cmtc-a `cilium-zhxjf` | 18:00:02.708Z, reason `lease ending` | 4.44 ms | 2026-10-29T17:11:21Z |
| cmtc-b `cilium-sg2wm` | 18:00:03.509Z, reason `lease ending` | 2.31 ms | 2026-10-29T17:13:56Z |
| cmtc-b `cilium-nhfk7` | 18:00:03.916Z, reason `lease ending` | 2.86 ms | 2026-10-29T17:13:56Z |

The new lease ends are each agent's own origin client certificate NotAfter (cmtc-a revision 5, cmtc-b revision 6):
the earlier of the two certificates, as designed. Watch 17:56:30Z to 18:04:30Z, one probe per second on 14 paths:
5,727 allowed probes, 0 failed, 480 probes from the unregistered callers, 0 answered, no `event=withdrawn` on any
agent. The old build would have withdrawn at the leaf's NotAfter (18:10Z); no old build was left to show it after
the cmtc-a upgrade.

## The outage on kind-cmtc-a, 17:11:55Z to 17:23:47Z

- The old build's R1 withdrawal at 17:11:55Z closed ztunnel's xDS stream to the agent (as every old-build
  withdrawal does). ztunnel's reconnect to the agent's ADS server (`localhost:15012`) failed:
  `invalid peer certificate: certificate expired: verification time 1793207515 (UNIX), but certificate is not valid after 1793189835`
  ([extract](outage-cmtc-a/ztunnel-cmtc-a-worker-xds.events); 38 such lines on the worker ztunnel). 1793189835 is
  2026-10-28T12:17:15Z, the NotAfter of `cmtc-ztunnel-ads-server` revision 3. cert-manager renewed it to revision 4 at
  11:17:15Z (24 h, `renewBefore: 1h`), but the agents, started at 04:19Z, still served revision 3.
- Cause in code: `pkg/ztunnel/xds/xds_server.go` `Serve()` calls `ca.LoadServerTLSCredentials()`, which returned
  `credentials.NewServerTLSFromFile(...)` (`pkg/ztunnel/ca/ca_server.go:77`): the pair is read once. Both
  `823d30c51b` and `ce5c3ec031` have it. The established xDS streams kept working, so nothing showed until a
  reconnect.
- Effect: both cmtc-a ztunnels NotReady from 17:12:24Z. Every allowed probe on cmtc-a failed (curl 52 and 56), and
  cmtc-b's probes into cmtc-a too ([R1-cmtc-a](R1-cmtc-a/README.md), [R1-cmtc-b](R1-cmtc-b/README.md)). The
  unregistered callers stayed denied. cmtc-b's own paths had 0 failures.
- Recovery: the agent restarts of the cmtc-a upgrade loaded revision 4 from disk. The upgrade watch's failures (56
  per cmtc-a path) all fall between 17:22:42Z and 17:23:38Z, the end of the outage; none after.
- Retraction: the R3 drill on cmtc-b at 16:45Z ([R3-cmtc-b](../R3-cmtc-b/README.md), 0 failed probes) did not prove
  the ADS renewal: no ztunnel reconnected. At 17:38Z both cmtc-b agents still presented revision 4 while the
  Certificate was at revision 5 (a fresh TLS handshake to `127.0.0.1:15012` from each node).

## Open

- The ADS fix: Cilium fork `c84f7d0741` (branch `fix/ztunnel-origin-credential-renewal`), which serves the pair on
  disk to each new handshake through `pkg/crypto/certloader`, image
  `cilium-dev@sha256:369090126600…dafa60` (CI run 40738186605). Under independent review; not deployed. Until it
  is, the agents hold ADS revision 4 in memory (cmtc-a NotAfter 2026-10-29T11:17:15Z, cmtc-b 11:17:16Z): any ztunnel
  reconnect after that is the same outage.
- The R3 drill must prove a new handshake presents the renewed ADS certificate (a patch is proposed).
- The old-build withdrawal at the server leaf's NotAfter was not observed live; it is confirmed from code by the
  review of `ce5c3ec031` (C8).
