# Issuer approval arbiter: live qualification on kind-cmtc-a and kind-cmtc-b, 2026-10-27

Record of [the runbook](../../development/ARBITER_QUALIFICATION_RUNBOOK.md), run by the live-writer session. Image:
`ghcr.io/ephico2real2/cmtc@sha256:a3efbe8c98249fbe931498edd9d35ab821bd7a506f6bbf33fbc0fb3ba7623719` (CI run 40554526163,
source `bb3cfd5`, artifact `cmtc-images-bb3cfd5…`).

## Step 2: kind-cmtc-a adopted into Helm, the arbiter off (17:56-18:01Z)

- First `cmtc_adopt.py plan`: the server-side apply fails with 6 conflicts (`kubectl-client-side-apply`: agent args,
  env `NODE_NAME`, `runAsNonRoot`, `runAsUser`; `kubectl-patch`: agent and controller image).
- `cmtc_adopt.py transfer`: 14 objects, managedFields only; first managedFields kept in
  `/private/tmp/cmtc-opus-final-20261025/review/cmtc-adoption-20261027T1800Z/`.
- Second plan: 87 changes, 0 kubectl manager entries left, 0 refusals. Spec changes: the image on both workloads; the
  node agent's trust-report args, mounts and uid 0; the controller's pod annotation `security.cmtc.io/live-issuer-owner`
  removed. Controller args unchanged.
- `helm upgrade --install cmtc … --server-side=true --take-ownership`: `STATUS: deployed`, `REVISION: 1` at 17:57:32Z.
- Controller log: `issuerProfileProducer=true issuerApprovalArbiter=false`; node agents `nodeTrustReport=true
  managePins=false`.
- NodeTrustReports `cmtc-a-control-plane`, `cmtc-a-worker`: pins `ReadOnly` with roots `0c28af9e…` and `6c12c735…`;
  ztunnel `Accepted`, generation 6, digest `5560480d…6bd9`, trusted issuers `2dee6086…e3d5` (cmtc-a) and
  `b9075e42…a006` (cmtc-b).
- Publication: `published 6 cmtc-issuer-approval-g6`, sequence 17797 at 17:58:27Z. ztunnel `lease fenced` lines in the
  5 minutes after the install: 0 on both nodes.
- [matrix-step2](matrix-step2/join.txt): 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed
  (probes 17:58:49-18:00:49Z).

Found: every node's pins file still holds the retired Lab Org Root `0c28af9e…`. With `managePins` the node agent
reports `WriteFailed`, which the arbiter refuses, so the lab values keep it off; the root is retired in the ztunnel fork
next (`/private/tmp/cmtc-opus-final-20261025/review/root-retirement/BRIEF.md`).

The root was retired on every node at 19:05-19:21Z
([root-pin-retirement-20261027](../root-pin-retirement-20261027/README.md)): the cmtc-a NodeTrustReports now read pins
`ReadOnly` with `6c12c735…` only; `managePins` stays off.

## Step 3: the peer credential of kind-cmtc-a on kind-cmtc-b (19:42-19:44Z)

- First run, 19:42:44Z: the script stopped after it created the token Secret on cmtc-a. Its go-template for the CA,
  `{{(index .clusters 0).cluster "certificate-authority-data"}}`, calls a field with an argument ("cluster is not a
  method but has arguments"). Fixed to `{{index (index .clusters 0).cluster "certificate-authority-data"}}`, checked
  first by decoding the CA alone (`CN=kubernetes`, to 2036-10-21).
- Second run, 19:43:14Z, exit 0: `installed cmtc-system/cmtc-peer-cmtc-a on kind-cmtc-b: cmtc-peer-reader of
  kind-cmtc-a at https://172.18.0.3:6443 (token Secret cmtc-system/cmtc-peer-reader-token on kind-cmtc-a)`. The token
  Secret is `kubernetes.io/service-account-token` for `cmtc-peer-reader`, filled; the reader's checks (Certificates
  yes, Secrets no) passed before the install. Nothing of the token was printed.
- Probe from a Pod on cmtc-b with cmtc-a's CA only: `/version` returned `200`, not the `401` the runbook expected.
  The expectation was wrong: on cmtc-a the ClusterRole `system:public-info-viewer` (`/healthz`, `/livez`, `/readyz`,
  `/version`) is bound to `system:unauthenticated`. `/apis` without a token returned `403` (the API server allows
  anonymous requests; RBAC refuses `system:anonymous`). Both prove TLS to `172.18.0.3:6443` verified with cmtc-a's CA.
  The runbook now expects `200`.

## Step 4: the arbiter on kind-cmtc-b (19:45-19:53Z)

- `cmtc_adopt.py plan`: 2 conflicts with `kubectl-patch` (controller args and image). `transfer`: 14 objects,
  managedFields only (backup `/private/tmp/cmtc-opus-final-20261025/review/cmtc-adoption-cmtc-b-20261027T1950Z/`).
  Second plan ([plan-2](step4/plan-2.txt)): 100 changes, 24 objects created, 0 kubectl manager entries, 0 refusals.
  The spec changes: the image on both workloads; the node agent's trust-report args, read-only mounts and uid 0; the
  controller's args lose `--issuer-profile-source` and `--issuer-profile-source-uid` and end with
  `--issuer-approval-config=/etc/cmtc/issuer-approval/config.json` (`adoptSource` `cmtc-issuer-approval-g6`); its
  volumes `issuer-approval-config` and `peer-cmtc-a`; the Role `cmtc-issuer-profile-access` names g6 and both slots.
- `helm upgrade --install cmtc … --server-side=true --take-ownership --wait`: `STATUS: deployed`, `REVISION: 1`,
  19:46:20-19:46:25Z. Controller log: `issuerApprovalArbiter=true`; no peer kubeconfig error.
- IssuerApproval `cmtc` ([watch](step4/issuerapproval-watch.txt), sampled every 3 s):
  - 19:46:36Z `Blocked`, `MeshNotConverged`: no node report fresh yet on either cluster (freshness needs a heartbeat
    seen by this controller);
  - 19:46:57Z the local nodes converged at generation 6; cmtc-a's control-plane report still stale;
  - 19:47:12Z `Publishing`: pending generation 7, reason `Adopt`, slot `cmtc-issuer-approval-a`, digest
    `e559a303…f3e1`, expires 2026-11-25T19:47:11Z;
  - 19:47:28Z `Converged`: current is that slot, pending empty, both local nodes accept generation 7.
- Approval `cmtc-issuer-approval-a` ([after](step4/after.txt)): generation 7, the same issuers as g6 (`2dee6086…` for
  cmtc-a, `b9075e42…` for cmtc-b). Generation 7 renews g6 (g6 expires 2026-11-25T10:26:41Z); the next renewal is due
  168 h before 2026-11-25T19:47:11Z, at 2026-11-18T19:47:11Z.
- Publication: `published 7 cmtc-issuer-approval-a`. cmtc-a still publishes g6.
- ztunnel, both nodes, 19:47:16.154Z: `approval-source-succession` from g6 to the slot, floors carried, no checkpoint
  reset. The in-session update is NACKed by design ("durable material change requires complete native ADS resync and
  drain"); the next session committed generation 7 19.5 ms later; `closed_connections=0`. `lease fenced`: 0 on both.
- NodeTrustReports: pins `ReadOnly` [`6c12c735…`], ztunnel `Accepted`, generation 7, digest `e559a303…`, trusted
  issuers unchanged.
- [matrix-step4](matrix-step4/join.txt), 19:49:18-19:53:20Z: 96 proven over mTLS, 0 unanswered, 36 dropped, 0 failed.
- Node report write restriction ([probe](step4/vap-probe.txt)): a Pod as `cmtc-node-agent` on `cmtc-b-worker` writing
  `not-my-node` got `403`, `denied request: a CMTC node agent may write only the NodeTrustReport named after the node
  its token is bound to`; `get nodetrustreport not-my-node`: `NotFound`.

## Step 5: the arbiter on kind-cmtc-a (19:54-20:00Z)

- Peer credential of kind-cmtc-b on kind-cmtc-a, 19:54:46Z ([output](step5/peer.txt)): `installed
  cmtc-system/cmtc-peer-cmtc-b on kind-cmtc-a: cmtc-peer-reader of kind-cmtc-b at https://172.18.0.4:6443`; probe from
  a Pod on cmtc-a to `/version`: `200`.
- `cmtc_adopt.py plan` ([plan](step5/plan.txt)): 14 changes, 0 kubectl manager entries, 0 refusals; only the
  controller Deployment's pod template changes (args, the config and `peer-cmtc-b` volumes); the node agents do not
  roll.
- `helm upgrade cmtc … --server-side=true --wait`: `REVISION: 2` at 19:55:19Z; controller log
  `issuerApprovalArbiter=true`.
- IssuerApproval ([watch](step5/issuerapproval-watch.txt)): `Blocked`, `MeshNotConverged` (stale reports) at
  19:55:24Z; `Publishing` generation 7 `Adopt` in `cmtc-issuer-approval-a`, digest `f3d0df12…1866`, expires
  2026-11-25T19:55:52Z, at 19:55:54Z; `Converged` at 19:56:10Z.
- Both clusters ([after](step5/after.txt)): record `Converged` at generation 7; publication `published 7
  cmtc-issuer-approval-a`; approval issuers `2dee6086…` (cmtc-a), `b9075e42…` (cmtc-b), as in g6; every report pins
  `ReadOnly` [`6c12c735…`], ztunnel `Accepted` 7; `lease fenced`: 0 on all four ztunnels; cmtc-a's ztunnels logged
  `approval-source-succession`, floors carried, no checkpoint reset.
- [matrix-step5](matrix-step5/join.txt), 19:56:34-20:00:36Z: 96 proven over mTLS, 0 unanswered, 36 dropped, 0 failed.
  The cmtc-a ztunnels logged 4 client-side "session expired or changed" handshake errors each, the pre-existing
  observation ([root-pin-retirement-20261027](../root-pin-retirement-20261027/README.md#observations)).

State after step 5: the arbiter is **deployed** on both labs by digest
`ghcr.io/ephico2real2/cmtc@sha256:a3efbe8c98249fbe931498edd9d35ab821bd7a506f6bbf33fbc0fb3ba7623719`; the adoption is
**traffic-qualified** by `matrix-step5`. Steps 6 (forced intermediate renewal, overlap, retirement) and 7 (recovery)
are not run.

## Step 6: the forced renewal of cmtc-b's SPIRE intermediate (from 20:02Z; in progress)

- Before ([before](step6/before.txt)): `cmtc-b-spire-intermediate` revision 1, notAfter 2027-10-26T12:49:42Z,
  `rotationPolicy: Always`; both records `Converged` at generation 7. SPIRE's trust bundle on cmtc-b holds two roots:
  the mesh root and the retired CMTC Lab Organization Root (to 2031-10-24). ztunnel pins only the mesh root; a
  verifier that uses SPIRE's own bundle still trusts the old root (open item).
- `cmctl renew` (cmctl v2.6.2, installed from Homebrew for this step) at **T_renew = 20:03:19Z**: revision 2, valid
  2026-10-27T20:03:19Z to 2027-10-27T20:03:19Z ([renew](step6/renew.txt)). Its CertificateRequest
  `cmtc-b-spire-intermediate-2` carries the new key, SPKI `3270f5a5…6fed`.
- Records ([watch](step6/watch-renewal.txt)): both arbiters wrote generation 8, `IssuerAdded`, slot
  `cmtc-issuer-approval-b`. cmtc-a: pending 20:03:39Z, `Overlapping` 20:03:55Z. cmtc-b: pending 20:03:58Z,
  `Distributing` 20:04:13Z, `Overlapping` 20:04:29Z. The old key `b9075e42…` "stays until 2026-10-28T21:03:27Z" on
  cmtc-b (21:03:22Z on cmtc-a): the first read plus 24 h `ca_ttl` plus 1 h margin.
- Generation 8 ([overlap](step6/overlap.txt)): cmtc-b has two issuers, `3270f5a5…` and `b9075e42…`; cmtc-a's issuer
  unchanged. Both publications `published 8 cmtc-issuer-approval-b`; every report on both clusters `Accepted` 8 with
  three trusted SPKIs; 0 `lease fenced`, 0 connections closed.
- SPIRE ([authority](step6/spire-authority-after-renew.txt), 20:06Z): active CA `a1348ce4…` under the old intermediate
  key (upstream `53d3ad70…`), expires 2026-10-28T10:52:42Z; no prepared CA. SPIRE prepares the next CA at half of the
  active CA's lifetime (2026-10-27T22:52:42Z) and activates it at five sixths (2026-10-28T06:52:42Z).
- [matrix-step6-overlap](matrix-step6-overlap/join.txt), 20:06:35-20:10:38Z: the join tool reports 95 proven over
  mTLS, 36 dropped, **1 failed**. The failed probe (cmtc-a `name`, `client-worker` to
  `server-worker.cmtc-live-mtls.svc.cluster.local:80`, 20:06:42.892-.964Z) returned HTTP 200 from the expected server
  (`curlRC` 0). curl reported its socket as `10.10.1.205:43064`, the port an earlier probe used 3.6 s before; ztunnel
  logged the connection from `10.10.1.205:20270` (below the ephemeral range: the source port was rewritten). The only
  outbound line from `client-worker` to `10.10.1.37:80` in the probe's window is that one, at 20:06:42.912Z, mTLS to
  `spiffe://cmtc-a.mesh.example/ns/cmtc-live-mtls/sa/rebel-base`, and no other probe claims it. So 96 of 96 allowed
  probes went over mTLS; one is joined by destination and time with one candidate, as in
  [matrix-g6](../spire-intermediate-20261027/matrix-g6/README.md). The join tool has no such fallback and counts it
  as failed.


## Step 7: recovery tests on kind-cmtc-b (20:12-20:27Z)

Run during the generation 8 overlap of step 6. Both ztunnels on cmtc-b logged 0 `fenced` lines in every window.

### 7.1 Controller restart (20:12:38Z)

[Record](step7/controller-restart.txt). The successor logged "Attempting to acquire leader lease" at 20:12:39.54Z and
"Successfully acquired lease" at 20:12:41.13Z (1.6 s). The publication kept sequence 18612 through the rollout, then
moved to 18613 at 20:12:46Z and on every 10 s. The record stayed `Overlapping`, current 8 in
`cmtc-issuer-approval-b`, nothing pending.

### 7.2 Node agent restart (20:13:38Z)

[Record](step7/node-agent-restart.txt). Both reports moved: `observedAt` 20:13:34Z and 20:13:35Z before, 20:13:39Z and
20:13:40Z after the rollout, with new `resourceVersion`s; at 20:14:57Z they were 20:14:49Z and 20:14:40Z. The record
stayed `Overlapping` 8, `NodesConverged=True` (`AllNodesAccept`). No report became older than `reportMaxAge` (2 min),
so the `Blocked` branch for a stale report was not exercised.

### 7.3 Peer unreachable: a defect found

The policy is a [CiliumNetworkPolicy](step7/no-peer-policy.yaml) on the controller Pod that allows egress only to
cmtc-b's own API (`toEntities: [kube-apiserver]`) and to kube-dns. A `NetworkPolicy` with an `ipBlock` cannot express
it here: CIDR selectors do not select cluster nodes unless `policy-cidr-match-mode` includes `nodes`
([Cilium Layer 3 policies](https://docs.cilium.io/en/stable/security/policy/layer3/)), the option is unset on both labs,
and both API endpoints are node IPs.

- **Run 1** ([record](step7/peer-unreachable.txt), policy 20:16:36-20:20:39Z, controller running): the record kept
  `EvidenceReady=True` (`AllClustersRead`) to the end. The controller's connection to cmtc-a's API, open before the
  policy, was not cut, so the run tested nothing. [matrix-step7-no-peer](matrix-step7-no-peer/join.txt),
  20:16:40-20:18:40Z: 96 proven over mTLS, 0 unanswered, 36 dropped by Cilium, 0 failed.
- **Run 2** ([record](step7/peer-unreachable-run2.txt), policy 20:22:41Z, then a controller restart, policy deleted
  20:24:46Z): the new controller opens a new connection, which the policy drops. The record kept the previous pass's
  `EvidenceReady=True` for the whole window. The [arbiter log](step7/peer-unreachable-run2-arbiter-log.jsonl) shows
  why: passes 1 to 3 each ran 30.0-30.2 s, longer than the 12 s pass timeout, and each ended `update the
  IssuerApproval status: context deadline exceeded`. Pass 4, at 20:24:59Z after the policy was deleted, was `idle` in
  0.023 s. Safety held: no slot written, current unchanged at 8, 0 fences; the producer kept publishing (sequence
  18673 to 18685).

**Cause.** The peer client is `client.New`, whose REST mapper discovers the API on a cache miss with
`GroupsAndMaybeResources()`, a call that takes no context (controller-runtime v0.24.1 `pkg/client/apiutil/restmapper.go:285`).
A fresh client has an empty cache, so the first read of a peer whose connection is dropped waits for client-go's 30 s
dial timeout (`k8s.io/client-go@v0.36.0/transport/cache.go:122`) while the pass deadline passes. The status write then
ran on the expired pass context. A peer that is down made the record report stale evidence as current.

**Fix** (implemented and unit-tested; not yet deployed):

- `cmd/cmtc/main.go` `peerReader`: the peer client's `rest.Config.Timeout` is `controller.PeerRequestTimeout` (4 s), so
  every request, discovery included, ends within 4 s. Discovery stops at its first failed request, and each read site
  stops at its first failed read, so a down peer costs a pass at most two requests (8 s of the 12 s).
- `internal/controller/issuer_approval.go` `Reconcile`: the status write has its own 5 s deadline on the runner's
  context (leader loss still cancels it), not the pass deadline.
- Tests: `cmd/cmtc/peer_reader_test.go` (a TLS peer that never answers: the first request is discovery, and it fails
  in 0.31 s at a 300 ms timeout; without the timeout the test hangs to the test deadline) and
  `TestIssuerApprovalArbiterReportsAPeerThatNeverAnswers` (a pass with a hanging peer and a 200 ms pass timeout writes
  `EvidenceReady=False` / `EvidenceMissing`, the peer's evidence `Unavailable`, no slot; with the status write on the
  pass context it fails with `update the IssuerApproval status: context deadline exceeded`).

A second finding of the same read: the peer client is built once, at start, from a kubeconfig with an inline token.
A replaced peer credential takes effect only after a controller restart; `scripts/lab/pki/peer-reader-credential.sh`
now says so.
