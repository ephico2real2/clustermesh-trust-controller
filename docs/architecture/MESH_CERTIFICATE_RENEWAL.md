# Renew every mesh certificate without a failed connection (#47)

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Status, 2026-10-28: the design for P1 and P2 of [#47](https://github.com/ephico2real2/clustermesh-trust-controller/issues/47)
(= [#46](https://github.com/ephico2real2/clustermesh-trust-controller/issues/46)) is **implemented and unit-tested**
in the Cilium fork, commit `ce5c3ec031b412a4b927bcba025f9ef269a41673` on branch `fix/ztunnel-origin-credential-renewal`
(from `823d30c51b`, the deployed agent source), built by the fork workflow run
[40719125969](https://github.com/ephico2real2/cilium/actions/runs/40719125969) as
`ghcr.io/ephico2real2/cilium-dev@sha256:8446cf910bdba8d0ef7760693a16b8536800de6e353456df6e6f7bca8969b2cc`
(tag `sha-ce5c3ec031b412a4b927bcba025f9ef269a41673-agent`, linux/amd64 and linux/arm64, revision label and
`cilium-dbg version` checked). It is **deployed and traffic-qualified on kind-cmtc-b** (Helm revision 12,
2026-10-28 16:26Z; drills R1 to R4 0 failed probes, no withdrawal:
[record](../evidence/cert-rotation-drills-20261028/README.md)) and **not yet deployed on kind-cmtc-a**, whose agents
stay on `823d30c51b` until the server-leaf-expiry prediction below is measured. Phase 2
([below](#phase-2-rollout-plan)) is the plan that cmtc-b followed. The rotation drill (P3) is **written and
dry-run** ([`scripts/evidence/rotation_drill.py`](../../scripts/evidence/rotation_drill.py)). P4 to P9 are **planned**.
cert-manager stays the issuer of every certificate (operator, 2026-10-28; [ADR-011](adr/ADR-011.md)).

## Result

A Cilium agent that reads a peer cluster's workloads directly from the peer's clustermesh-apiserver etcd (the
direct-origin reader) no longer withdraws the peer when its own client certificate is renewed. The etcd client
already reloads the certificate and key from disk at every TLS handshake, as upstream Cilium does. So a renewal is
taken up by a new handshake on the same session, not by a new session: the agent closes its pinned TLS sockets, gRPC
redials at once, etcd's watch client resumes each watch at its last revision, and the snapshot is never invalidated.
The same in-place re-handshake runs ten minutes before the session's lease ends, so a session never outlives the
NotAfter of the certificate that either side presented. Every real trust failure still withdraws the peer.

## What a renewal does today

Measured on kind-cmtc-a and kind-cmtc-b with the agent from `823d30c51b` (inventory R1 to R8 in #47):

| Credential | Renewal | Effect today | Why |
|---|---|---|---|
| R1 `ztunnel-origin-reader`, 24 h, renewed 1 h early | daily per cluster | every agent withdraws the peer's workloads for 270 to 311 ms (2026-10-28), or 0.4 s to 10 s (2026-10-26, [finding 08](../evidence/clustermesh-pki-20261026/cutover/08-finding-origin-reader-renewal.md)) | the supervisor hashed the certificate and key into the session fingerprint (`origin_supervisor.go`, `Load`) and restarted the session; the restart wait is its retry backoff, which doubled on every retry and was never reset (`origin_supervisor.go:674` at `823d30c51b`), so a 36 s peer outage on 2026-10-26 ratcheted it to the 10 s cap |
| R4 `clustermesh-apiserver-server-cert`, 24 h, renewed 8 h early (`status.renewalTime` = NotAfter - 8 h, no `renewBefore` set) | every 16 h | no withdrawal at the renewal (13:48Z and 13:51Z, 2026-10-28) | the agent sees a server leaf only at a handshake |
| R4, the previous server leaf's NotAfter | 8 h after each renewal | **predicted, not yet measured:** every established origin session is withdrawn | the fork's evidence lease is the server leaf NotAfter seen at the handshake (`pkg/kvstore/remote_peer_identity.go`, `evidenceAt`); the sessions opened at 11:48Z and 11:51Z on 2026-10-28 carry the leaves issued on 2026-10-27 at 21:48:06Z (cmtc-a) and 21:51:07Z (cmtc-b), so `event=withdrawn` with `pinned remote peer certificate expired` is expected on the cmtc-b agents at 21:48Z and on the cmtc-a agents at 21:51Z on 2026-10-28, unless something reconnects them first |

No agent logged a withdrawal between 12:00Z and 15:10Z on 2026-10-28 (all four agents read).

## How Istio ambient, Linkerd and upstream Cilium consume a renewed credential

Source read on 2026-10-28 at the tags named in the #47 research comment, re-verified line by line for this note.
The research comment's claims hold; the line numbers below are the verified ones.

| Question | ztunnel 1.31.3 / istiod 1.31.3 | Linkerd proxy v2.372.0 / linkerd2 edge-26.10.1 | Cilium v1.20.4 |
|---|---|---|---|
| When is a leaf renewed | at half of its lifetime (`src/tls/certificate.rs:402-408`); on failure the old leaf is kept and the retry backs off from 500 ms to 150 s with jitter 0.2 (`src/identity/manager.rs:39,369-401`, PR [#1567](https://github.com/istio/ztunnel/pull/1567)) | at 70 % of the remaining lifetime, between `min_refresh` and `max_refresh` (`linkerd/proxy/identity-client/src/certify.rs:191-203`); on failure the old leaf is kept (`certify.rs:118-131`) | cert-manager `renewBefore`; the chart sets 1 h of 24 h for the ztunnel certificates (`values.yaml:1330,1351,1373` at `1bd555f313`) |
| Is a renewed leaf validated before use | — | yes, with the client's own verifier, before it is published (`linkerd/meshtls/src/creds/store.rs:128-163`) | the agent's loader verifies the chain and the EKU before a session may use the files (`origin_supervisor.go`, `Load`) |
| How a new leaf reaches connections | per connection: inbound fetches the certificate per accepted connection (`src/proxy/inbound.rs:760-774`), outbound per new pooled connection (`src/proxy/pool.rs:83-86`); established connections keep their leaf | per connect (`linkerd/tls/src/client.rs:137-139`); established connections keep their leaf | per handshake: `GetClientCertificate` runs `tls.LoadX509KeyPair` (`pkg/kvstore/etcd.go:411-422,1700-1714`); no reconnect, no restart |
| Client credential to the control plane | a bearer token read at each request, no client certificate (`src/tls/control.rs:183-199`, `src/identity/auth.rs:29-41`); the xDS TLS config is built per stream connect (`src/xds/client.rs:650-655`); a reconnect resumes with `initial_resource_versions` (`client.rs:232-236,612-635`) | the proxy's own workload identity (`linkerd/app/core/src/control.rs:99-127`); the discovery stream holds its endpoints and the first `Add` after a reconnect becomes a `Reset` (`linkerd/proxy/resolve/src/recover.rs:163-171`) | the per-handshake reloader above; the config-directory watcher hashes only the config file (`pkg/clustermesh/common/config.go:155-169`), so a renewed certificate causes no event at all |
| Root or CA change | the CA channel is rebuilt and swapped, the old one kept if the rebuild fails (`src/identity/caclient.rs:108-135`, PR [#1775](https://github.com/istio/ztunnel/pull/1775)); istiod accepts a new root only with `ISTIO_MULTIROOT_MESH` and only when the old and new bundles are subset and superset (`pilot/pkg/bootstrap/istio_ca.go:362-374`) | the identity controller verifies a new issuer against the anchors and keeps the old one when that fails (`pkg/identity/service.go:106-118,134-141`); the proxy's trust anchors come from `LINKERD2_PROXY_IDENTITY_TRUST_ANCHORS` (`linkerd/app/src/env.rs:222`; that they are read once was not re-verified here) | the client's `RootCAs` pool is built once, when the client is created (`vendor/go.etcd.io/etcd/client/v3/yaml/config.go:83`); a changed CA file is taken up only by a new client, which is why the fork makes a CA change a trust (`Fingerprint`) change that restarts the session |
| A remote-cluster credential | istiod builds the new cluster while serving the old one, swaps after the new one syncs, then stops the old one (`pkg/kube/multicluster/secretcontroller.go:440-449`, `clusterstore.go:90-116`, `cluster.go:171-195`; PR [#58567](https://github.com/istio/istio/pull/58567) for [#49349](https://github.com/istio/istio/issues/49349)); defect [#61043](https://github.com/istio/istio/issues/61043) (the old registry's close removed the new one's endpoints, fixed by [#61044](https://github.com/istio/istio/pull/61044)); [#62408](https://github.com/istio/istio/issues/62408) is open | service-mirror restarts its watcher on a Link change only and keeps the mirrored Services (`multicluster/cmd/service-mirror/main.go:183-212`); destination has no update handler for the mirror Secret (`controller/api/destination/watcher/cluster_store.go:113-160`) | a config-hash change or a watchdog error releases the old connection and reconnects (`pkg/clustermesh/common/remote_cluster.go:114-141,264-298`); watch stores mark every key stale and delete only the still-stale keys after the list (`pkg/kvstore/store/watchstore.go:154-170`); a remote identity cache is registered only after its list is done (`pkg/allocator/allocator.go:1109-1162`) |
| Bounded staleness | none found | none found | `clustermesh-cache-ttl`, off by default (`pkg/clustermesh/common/config.go:38`, PR [#41643](https://github.com/cilium/cilium/pull/41643)) |
| Known failures | [#1966](https://github.com/istio/ztunnel/issues/1966): 1.7 to 4.9 s data-plane stalls during a full re-insert at scale; [#1679](https://github.com/istio/ztunnel/issues/1679) (open): root rotation with AWS PCA | [#15109](https://github.com/linkerd/linkerd2/issues/15109): a missed fsnotify event left an expired issuer in use | — |

What the fork did differently from all three: it re-read the credential files every 2 s and treated a change of the
certificate or key as a change of trust (a new session with a withdrawal), and it treated a renewed server leaf for
the same key as a new identity (`remote_peer_identity.go`, `connectionOpened` at `823d30c51b`: the identity epoch
changed when the NotAfter changed). Both are stricter than any of the three meshes, and neither adds security: the
pin is the server's public key, and the client's own credential is verified by the server at the handshake.

Go's TLS, like rustls, does not verify again after the handshake. All three meshes accept that an established
connection outlives the NotAfter of the leaf it presented; none re-handshakes a long-lived control-plane connection
before NotAfter (istiod's 30-minute maximum connection age is the closest). This design does re-handshake before
NotAfter, because the fork's evidence lease makes the server leaf's NotAfter a hard deadline anyway.

## Design: A, plus an in-place re-handshake (chosen)

Of the two candidates in #47, **A** (upstream Cilium's method: reload per handshake, no reconnect) is chosen, with
one addition for the NotAfter policy. **B** (a standby session listed in parallel and swapped) is not built: it needs
the joiner and inventory to stage a second list and the xDS projection to swap atomically, the earlier #46 attempt
stalled on exactly that, and A removes the daily cost without a second list. B stays the fallback if the live drill
shows the re-handshake is not hitless.

Code (fork commit `ce5c3ec031`):

1. **The fingerprint is split** (`pkg/ztunnel/remote_workload/origin_supervisor.go:85`, `Load`). `Fingerprint`
   covers the trust of a session: the peer name, the ClusterID, the config file (endpoints, pin, host aliases, file
   names) and the trusted CA bundle. A change restarts the session with a withdrawal, as before.
   `CredentialFingerprint` covers the client certificate and key only. A change is a renewal.
2. **A session has a lease** (`originSessionLease`, `origin_supervisor.go:694`): the earlier of the client
   credential's chain end and the peer's server leaf NotAfter, both as presented at the session's last handshake. The
   client side is bounded by the profile loaded at the same poll as the handshake (the etcd client reads the same
   files), the server side by the live evidence.
3. **The transport is refreshed in place** (`monitorSession`, `origin_supervisor.go:961-1040`) when the credential
   files change and when the lease is within `originRefreshLead` (10 minutes, `:52`), at most once per
   `originRefreshRetry` (1 minute, `:60`). The refresh is `kvstore.RemotePeerTransportRefresher`
   (`pkg/kvstore/remote_peer_identity.go:180`, implemented at `:555` and `:342`): the etcd client closes its pinned
   sockets; gRPC moves the subchannel to IDLE and etcd's `round_robin` policy (built on endpoint sharding and
   pick-first in grpc v1.84.0) reconnects at once without waiting for an RPC
   (`vendor/google.golang.org/grpc/clientconn.go:1519`, `balancer/endpointsharding/endpointsharding.go:352`,
   `balancer/pickfirst/pickfirst.go:355,656`, `vendor/go.etcd.io/etcd/client/v3/internal/resolver/resolver.go:44`;
   corrected after the OB2 review: `balancer/base` is not the path); the handshake presents the certificate the
   per-handshake reloader reads from disk now; etcd's watch client, on the stream's receive error, opens a new watch
   stream with `WaitForReady` and resumes every substream from its last revision without closing the caller's channel
   (`vendor/go.etcd.io/etcd/client/v3/watch.go:667-679,928-935,1042`); the fork's own watch loop relists only on a
   watch error (`pkg/kvstore/etcd.go:697-945`). The session, its watches, its leases, the
   inventory and the snapshot are untouched. The evidence of the closed transport stays usable for a bounded grace
   (`originRefreshGrace`, 5 s, `:56`), only during a refresh the client started itself, so that the 2 s evidence poll
   of the supervisor and the 5 s guard of the watch pair do not report the redial as a lost peer.
4. **The identity epoch changes only when the server's SPKI changes** (`remote_peer_identity.go:302`). A server leaf
   renewed for the same key, as `clustermesh-apiserver-server-cert` is (`rotationPolicy: Never`, the peers pin its
   key), is the same identity with a later NotAfter. The lease over several active transports is still the earliest
   NotAfter (`currentProofLocked`, `:397`), so a new transport never extends an old one.
5. **The retry backoff restarts** at `RetryMin` after a session whose inventory delivered a complete list
   (`OriginPeerWatchSession.Listed`, `origin_supervisor.go:585,605,840`). An earlier peer outage no longer makes the
   next restart wait the 10 s cap (P1).

### NotAfter policy for an established session

A session never serves past the NotAfter of the certificate that either side presented at its last handshake:

- The lease end is `min(client chain end at the handshake, server leaf NotAfter at the handshake)`.
- Ten minutes before the lease end the transport is re-handshaked. With cert-manager's `renewBefore` of 1 h for the
  client certificate and 8 h for the server certificate, the renewed certificate is on disk or served long before
  that, so the new handshake extends the lease by a full lifetime. `renewBefore` must stay longer than ten minutes.
- A credential change on disk is also taken up at once (the next 2 s poll, at most one refresh per minute). So a
  renewed client certificate is in use within a minute, and a credential the peer refuses is found while the old one
  still has an hour of validity, not ten minutes before it expires.
- If the lease end passes without a fresh handshake, the session is withdrawn (`errOriginLeaseExpired`,
  `origin_supervisor.go:66`) and the supervisor restarts it. If a refresh is not followed by a handshake within the
  grace, or the new transport does not prove the same pinned identity, the session is withdrawn at once: the old
  transport is closed and nothing proves the peer.

This differs from the second acceptance criterion of #46 as written ("the new session fails to list, the old
session is kept until its own certificate expires"), which presumes design B. Under this design a refused renewal is
a failed handshake, not a failed list, and the peer is withdrawn at once rather than kept on the old transport; the
criterion's purpose, no admission past the old certificate's validity, holds in both.

### Fail closed, kept

| Case | Where it is caught | Test |
|---|---|---|
| CA bundle, pin, endpoint, ClusterID or config change | `Fingerprint` differs: session restart with withdrawal | `TestOriginSupervisorRotatesConfigAndRequiresFreshSession`, `TestFilesystemOriginPeerConfigLoaderSeparatesTrustAndCredentialFingerprints` |
| Credential on disk invalid: wrong CA, wrong EKU, key mismatch, expired, bad mode | `Load` fails: `origin config invalid`, withdrawal | `TestFilesystemOriginPeerConfigLoaderRejectsInvalidProfiles` and siblings |
| Lease end reached without a handshake | `monitorSession`: `direct-origin session lease expired` | `TestOriginSupervisorWithdrawsAtTheLeaseEndWithoutARefresh` |
| Refresh without a handshake (peer refuses the renewed certificate, or is down) | `RefreshRemotePeerTransport` error: `direct-origin transport refresh failed` | `TestOriginSupervisorWithdrawsWhenTheTransportRefreshFails`, `TestRemotePeerTLSBindingRefreshWithoutHandshakeFailsClosed` |
| Server key changed (another pinned key) | identity epoch changes: withdrawal and a full list, as before | `TestOriginSupervisorReconnectsOnTLSIdentityEpochChange`, `TestRemotePeerTLSBindingTracksCertificateIdentityEpoch` |
| Server leaf expired, heartbeat stale, peer down | `evidence.Validate`, unchanged | `TestRemotePeerEvidenceExpiresWithCertificateOrHeartbeat` |

### Tests

`go test -race` in `golang:1.27` (arm64): `pkg/kvstore`, every `pkg/ztunnel/...` package and
`pkg/clustermesh/common` pass; `go build ./...` passes. In `pkg/kvstore` and `pkg/ztunnel/remote_workload` 123
top-level tests pass (225 with subtests), 9 of them new. Each new guard was reverted once and its test failed
(`p47/mutations.py`, five mutations: backoff reset, credential in the restart fingerprint, lease end, epoch on
NotAfter, refresh grace).

## P3: the rotation drill

[`scripts/evidence/rotation_drill.py`](../../scripts/evidence/rotation_drill.py) runs one credential renewal on one
cluster under the probe traffic of both clusters, once per second per path, in every scope (same node, cross node,
cross cluster, Global Service local and remote, per-Pod name, and the unregistered caller), with the Cilium agent and
ztunnel lines that matter captured as they happen (the ztunnel `Fetching PID` flood is dropped). It writes
`summary.json`, `traffic.jsonl`, `logs/` and a README table, and exits 1 on a failed verdict.

| Drill | Command it runs | Verdicts |
|---|---|---|
| R1, R2, R3 | `cmctl renew -n kube-system <certificate>` | certificate revision advanced and Ready; 0 failed allowed probes; denied path never answered; no `event=withdrawn` on any agent |
| R4 | `cmctl renew` of the admin, local, remote and then the server certificate, 10 s apart | same |
| R5 | `scripts/lab/spire/local_authority.py <cluster> rotate` | same, and `rotate` exit 0 |
| R6 | none: one SVID lifetime (150 s window) is observed | same, and every ztunnel's workload certificate serials changed |
| neg-ca | `ztunnel-origin-reader` reissued by a throwaway self-signed CA for 60 s, then the issuerRef put back and the CA removed | this cluster withdrew the peer; the cross-cluster path into this cluster failed closed (curl 56, never HTTP 200) and recovered; every other path 0 failed; the Certificate spec put back |
| neg-pin | a wrong `spki-sha256` for the peer in `ztunnel-origin-config` for 60 s, then the data put back byte for byte | same, with the ConfigMap data put back |
| neg-peer-down | `iptables DROP` of the peer's node port 32379 on this cluster's nodes for 120 s, then lifted | same, and no DROP rule left |

Nothing runs against a cluster without `--execute`. The two drills that patch Helm-managed objects refuse to run
without `--allow-helm-object-change`, and `scripts/lab/cilium_adopt.py plan` must report 0 afterwards (the patch
leaves the manager `cmtc-rotation-drill` on the field; `cilium_adopt.py transfer` moves it to Helm if needed).

Dry run, 2026-10-28T15:5xZ, read-only: `preflight` found `kubectl`, `cmctl` and `docker`, both kube-system UIDs,
two agents and two ztunnels per cluster and the eight fixture Pods; `drill R1|R4|R6|neg-peer-down --cluster cmtc-a`
without `--execute` printed the plan and changed nothing; `drill neg-ca --execute` without the flag was refused
before any probe or event started.

The "expired client certificate is refused" case of #47 is covered by the unit tests (`Load` and
`validateOriginPeerProfile` refuse an expired leaf) and, live, by neg-ca, which exercises the same `Load` refusal.
An expired leaf signed by the real intermediate cannot be produced without that intermediate's key, which is never
extracted.

## Phase 2: rollout plan

Preconditions: the orchestrator's go; the lab lease; no cluster access between 18:40Z and 19:15Z on 2026-10-28; the
image digest from the fork workflow run (`cmtc-development-images.yaml`, `images.lock.json` artifact).

1. Lock. In `config/cilium-images.lock.json` set `images.agent` to
   `ghcr.io/ephico2real2/cilium-dev@sha256:8446cf910bdba8d0ef7760693a16b8536800de6e353456df6e6f7bca8969b2cc`, `tag`
   `ghcr.io/ephico2real2/cilium-dev:sha-ce5c3ec031b412a4b927bcba025f9ef269a41673-agent` and `source_sha`
   `ce5c3ec031b412a4b927bcba025f9ef269a41673`. The chart source stays `1bd555f313` (the agent's chart renders the
   same; `prepare.py` allows a per-role source). Pull the image by digest and check
   `org.opencontainers.image.revision` and `cilium-dbg version`.
2. Render: `bash scripts/cilium/prepare.sh`; `scripts/lab/cilium_cluster_values.py ... cmtc-b --from-live`;
   `scripts/lab/cilium_release.py check ... --strict`: the only difference must be the agent image in the `cilium`
   DaemonSet pod template.
3. Plan: `scripts/lab/cilium_adopt.py plan ... cmtc-b`: the same one change, 0 deletions, 0 refusals, no field a
   kubectl manager owns.
4. Before the upgrade, measure the prediction: `kubectl logs` of all four agents for `event=withdrawn` after 21:48Z
   (the server leaf expiry, [above](#what-a-renewal-does-today)).
5. Upgrade kind-cmtc-b under the traffic watch: start `rotation_drill.py drill R6 --cluster cmtc-b --seconds 600
   --execute` (no event, probes and log followers only) and run `scripts/lab/cilium_adopt.py upgrade ... cmtc-b` in
   its window. Expected: the agents restart one at a time; the failures of the allowed paths lie inside the agent
   restart windows and nowhere else; the new agents log `Direct-origin transport refreshed in place` only when a
   credential changes or a lease ends.
6. Check: `cilium_release.py check ... cmtc-b`: 0 differences. `scripts/evidence/run_mtls_matrix.sh`: 96 proven
   over mTLS, 36 dropped, 0 failed. Record the Helm revision.
7. Drill on kind-cmtc-b: `rotation_drill.py drill R1 --cluster cmtc-b --execute` (the acceptance of #46), then R2,
   R3, R4. Expected on R1: `Direct-origin transport refreshed in place` on both cmtc-b agents within a minute of the
   renewal, 0 failed probes, no `event=withdrawn`. R4 also moves the server-leaf lease: the next refresh for the
   lease end is due 10 minutes before the old leaf's NotAfter.
8. Repeat 3, 5, 6, 7 for kind-cmtc-a.
9. The negative drills on one cluster: neg-ca, neg-pin (both with `--allow-helm-object-change`, then
   `cilium_adopt.py plan` 0 changes), neg-peer-down. Each must show the withdrawal, the denied traffic without
   plaintext, and the recovery.
10. R5 (one cluster at a time, not between a SPIRE CA activation and its matrix) and R6.
11. Record under `docs/evidence/cert-rotation-drills-20261028/`, update finding 08, `MESH_PKI.md` (findings,
    lifetimes) and `docs/agile/DELIVERY_STATUS.md`, and close #46 with the record.

Rollback: set `images.agent` back to `c77bdc52d2f3…ac8a447` (`823d30c51b`) in the lock, `prepare.sh`,
`cilium_adopt.py plan` (the one image change back), `cilium_adopt.py upgrade`, `cilium_release.py check` 0, matrix.
The change is agent-only; no object, Secret, Certificate, checkpoint, floor or ledger is touched.

## P4 to P9: plan

| Problem | What is built | Evidence that closes it |
|---|---|---|
| P4 ztunnel side of R3 and R6 | first, stop the `Fetching PID` flood: find its source in the ztunnel fork (`src/inpod` or the CMTC ZDS path), make it `debug`, and add a counter metric; then read `src/xds/client.rs` and `src/identity/manager.rs` of the fork for the ADS-server-certificate and CA-bundle paths and record them | `rotation_drill.py drill R3` and `R6` with the ztunnel followers: the `Stream established` and certificate lines across the event; ztunnel logs that still hold 30 minutes of history |
| P5 SPIRE CA activation without a gap | nothing new if the measurement is clean: SPIRE prepares the next CA at 1/2 and activates at 5/6, the bundle holds it from the preparation (`local_authority.py`, LOCAL_ISSUER_PROFILE.md) | the next clean activation (about 18:53Z on 2026-10-28, orchestrator's matrix queued at 18:58Z) with `drill R5` on a later day: 0 failed probes, no `withdrawn`, the new CA in every ztunnel chain within two minutes |
| P6 SPIRE outage tolerance | a recommendation, from data: the SVID TTL (120 s today; a 1 h TTL gives 30 minutes of SPIRE outage tolerance and 1 h of revocation delay; Istio uses 24 h) and the server's availability (one replica, `OrderedReady`, the #41 outage) | the 2026-10-28 outage record; a measured outage of 10 minutes with the registrar TTL raised on one namespace |
| P7 intermediate and root rotation drills | an `R7` drill: `cmctl renew cert-manager/<cluster>-clustermesh-intermediate` (new key) under probes, after checking that every verifier holds the root, not the intermediate; an `R8` dry-run procedure for the root: bundle the old and new roots in trust-manager, wait for every consumer, switch the issuers, retire the old root (the ordering rule of the research) | R7 live on one cluster: 0 failed; R8 as a written, dry-run-tested procedure |
| P8 lifetimes | after P1 to P3 are deployed: ClusterMesh 365 d on the labs (`live-labs.yaml` to `base.yaml`), the origin-reader, membership-writer and ADS lifetimes with `renewBefore` per the CA rule in MESH_PKI.md (each CA renews a full lifetime of what it signs before it expires; `renewBefore` longer than the 10-minute refresh lead) | `cilium_adopt.py plan` showing only the Certificate changes; the drills again at the new lifetimes |
| P9 rotation observability | a `cmtc_certificate_not_after_seconds{certificate}` gauge and `..._renewals_total` from the CMTC controller (cert-manager Certificates it can read), and the agent's origin events (`refresh-origin-transport`, `restart-origin-watch`, `event=withdrawn`) as counters on the observability v2 hub | a dashboard panel per certificate with time to expiry, and one with withdrawals per agent, qualified in both themes |

## Open risks

1. The in-place re-handshake is proven in unit tests and by reading gRPC and etcd's client, not yet on the labs. The
   live R1 drill decides it. If a transport gap shows as a failed probe, B is the fallback.
2. The 5 s grace returns the closed transport's evidence while gRPC redials. It is bounded, it is only after a
   refresh the client started, and the heartbeat and NotAfter checks still apply to it; a reviewer should read
   `currentProofLocked` with that in mind.
3. After a credential change the refresh waits for the next 2 s poll and at most one minute after the previous
   refresh or the session open. A credential that changes twice within a minute is taken up at the second minute.
4. `renewBefore` shorter than 10 minutes would make the lease-end refresh present the old certificate; the refresh
   then repeats once a minute until the renewed one is on disk, and the session is withdrawn at the old NotAfter.
   cert-manager's minimum is 5 minutes; the chart's 1 h is fine.
5. The R4 server-leaf expiry withdrawal is a prediction for tonight; if it does not happen, something reconnects the
   sessions that this note has not found, and the design note must say what.
6. The negative drills neg-ca and neg-pin patch Helm-managed objects and need the drift check after them; a failed
   revert (for example a lost connection mid-drill) leaves the object changed until it is put back by hand from the
   saved `*-before.json`.
