# Move ClusterMesh onto the cert-manager mesh root (2026-10-26)

**Status: executed** on kind-cmtc-a and kind-cmtc-b, 2026-10-26 12:48-13:51Z, steps 0-8. Steps 9 and 10 are open.
Design: [ADR-011](../../architecture/adr/ADR-011.md). Guide: [MESH_PKI.md](../../../MESH_PKI.md). Evidence:
[cutover/](cutover/). Every write is in the operations log quoted in the evidence files.

## Why

The ClusterMesh intermediates from the old `scripts/lab/up.sh` expired on 2026-10-26 at 19:37:39Z (cmtc-a) and
19:37:43Z (cmtc-b), and their root key had been deleted by design. The ADS certificates the agents served expired at
15:50:45Z and 15:50:47Z. After the cutover no live certificate depends on that chain.

## Trust inputs and issued certificates

Every ClusterMesh verifier reads `kube-system/cmtc-public-root` key `ca.crt`: the Cilium agent
(`common-etcd-client-ca.crt`, `clustermesh-origin/ca.crt`, `ztunnel-membership/ca.crt`), KVStoreMesh, the
clustermesh-apiserver (`etcd-server-secrets/ca.crt`, `etcd-admin-client/ca.crt`) and ztunnel
(`/etc/ztunnel/bootstrap-ca.crt`). No mount uses `subPath`, so the kubelet refreshes every projection. 7 Certificates in
`kube-system` per cluster: the 4 clustermesh-apiserver certificates (Helm), and `cmtc-ztunnel-ads-server`,
`ztunnel-membership-writer`, `ztunnel-origin-reader` (lab activation script).

## Reload behavior (source-checked, Codex review 2026-10-26)

| Verifier or server | Reloads `ca.crt` or its own certificate? | Source |
|---|---|---|
| clustermesh-apiserver etcd server | Client CA pool loaded once; its own leaf reloads per handshake | vendored `etcd/client/pkg/v3/transport/listener.go:472,529` |
| Cilium agent and KVStoreMesh etcd clients | Root pool loaded at client construction | `pkg/kvstore/etcd.go:429`, `pkg/clustermesh/common/config.go:226` |
| Direct-origin client | Reloads: hashes CA, certificate and key every 2 s and rebuilds the client | `pkg/ztunnel/remote_workload/origin_supervisor.go:163,876` |
| Cilium agent ADS server (`127.0.0.1:15012`) | Its certificate is loaded once, at `Serve()` | `pkg/ztunnel/ca/ca_server.go:77-78` |
| ztunnel ADS client | Reads `/etc/ztunnel/bootstrap-ca.crt` on every reconnect | ztunnel `src/xds/client.rs:813`, `src/tls/control.rs:42` |

The clustermesh-apiserver's etcd data directory is an `emptyDir`: a restart starts an empty etcd. `etcd-init` recreates
the ztunnel users (`--etcd-create-ztunnel-membership-users=true` on both clusters).

## Procedure as executed

Explicit contexts `kind-cmtc-a` and `kind-cmtc-b`. Each step on both clusters before the next. Every restart and reissue
ran under `lifecycle_event.sh` (continuous traffic on 8 paths, per-request join); the matrix
(`run_matrix.sh`) ran after steps 0, 4, 7 and 8.

0. **Preflight** ([00-preflight.txt](cutover/00-preflight.txt)): for the 7 Certificates, generation, revision, Ready,
   Issuing, pending requests, renewal time and SPKI; the root fingerprints in `cmtc-public-root`. Found: the server
   Certificates had no `rotationPolicy` (cert-manager v1.21 default `Always`).
   Baseline matrix: 48 proven over mTLS, 12 denials; `global` probes HTTP 200 but not attributable to one connection
   (cmtc-a), and the known DNS timeout (cmtc-b).
1. **to 3. Root, copy, intermediates.** `bash scripts/lab/pki/mesh-pki.sh --root-out cutover/cmtc-mesh-root-ca.crt
   cmtc-a cmtc-b` ([01-mesh-pki.txt](cutover/01-mesh-pki.txt)). Root `CN=cmtc mesh root CA`, SHA-256 `6c12c735…275f`,
   to 2036-10-23. Only new objects; no live leaf changed.
4. **Bundle overlap.** JSON patch of `cmtc-public-root` `ca.crt` to the disposable root followed by the mesh root, with
   `test` on uid, resourceVersion and the old value ([04-bundle.txt](cutover/04-bundle.txt)). All 22 CA projections (4 agents × 3, 2 apiservers × 3, 4 ztunnel × 1) held
   both roots by 13:08:45Z ([04-projections.txt](cutover/04-projections.txt)). Matrix unchanged.
5. **Keep the server key.** `spec.privateKey.rotationPolicy: Never` on `clustermesh-apiserver-server-cert`. Generation 2,
   revision unchanged, SPKI unchanged ([05-server-key.txt](cutover/05-server-key.txt)).
6. **Switch and reissue the ADS certificate.** `cmtc-lab-intermediate` was repointed to
   `<cluster>-clustermesh-intermediate`. Then `cmtc-ztunnel-ads-server` moved its `issuerRef` to
   `<cluster>-clustermesh-intermediate` ([06-switch.txt](cutover/06-switch.txt)). A changed `issuerRef` reissues the
   Certificate and keeps the key under `Never` (measured on a throwaway Certificate,
   [issuerref-test.sh](cutover/issuerref-test.sh)), so the move replaces the manual reissue.
7. **Reload the verifiers.** Restart the clustermesh-apiserver, then each Cilium agent, one node at a time
   ([restart-apiserver.sh](cutover/restart-apiserver.sh), [cmtc-b-step7.sh](cutover/cmtc-b-step7.sh)). **Run the agent
   restarts right after the apiserver restart:** until an agent restarts, the same cluster's crossnode traffic is
   refused ([finding](cutover/07-finding-local-source-watch.md)). cmtc-a was done with a gap: crossnode refused
   from 13:18:43.95Z in every measured window until 13:28:51.91Z (three events; the gaps between them were not
   measured). cmtc-b as one event: crossnode refused 13:33:12.17-13:35:16.99Z, cross-cluster 13:33:11.77-13:33:47.76Z
   (36 s). Each agent restart also cost its node 10-11 s of same-node and cross-cluster requests. Each agent
   then served the ADS certificate from its cluster's intermediate, to 2026-10-27T13:17Z
   ([07-ads-served.txt](cutover/07-ads-served.txt)).
8. **Move the other 6 Certificates,** one at a time, the server last ([step8.sh](cutover/step8.sh),
   [migrate.sh](cutover/migrate.sh)). Each: revision +1, Ready, chain to the mesh root, issuer CN printed. Server SPKI
   unchanged on both clusters (cmtc-a `d1a0d97f…`, cmtc-b `0822f405…`). The origin-reader reissue cost 49 cross-cluster
   requests on cmtc-a (13:47:58-13:48:07Z) and 1-2 on cmtc-b ([finding](cutover/08-finding-origin-reader-renewal.md)).
   Matrix after: 48 proven over mTLS, 12 denials, all 24 `global` probes HTTP 200.
9. **Persist (open).** The release values need the per-cluster `certManagerIssuerRef.name`, the server `privateKey`
   value (fork commit `64a07d46a6`, not deployed), `certValidityDuration: 365` and both roots in `tls.caBundle.content`.
   Until then no `helm upgrade` may run: it would restore the issuer name `cmtc-lab-intermediate`, the old bundle and the
   key rotation. Then delete `cmtc-lab-intermediate`.
10. **Retire the disposable root (open)** before 2026-10-27T19:37Z: inventory every consumer of `cmtc-public-root`;
    apply the mesh-root-only bundle; restart as in step 7; check that an old-only chain is refused and traffic passes.

## Helpers

[migrate.sh](cutover/migrate.sh) moves one Certificate to its cluster's issuer, guarded by `test` on uid,
resourceVersion and the old issuer name, and proves the result. A manual reissue without an issuer change uses a JSON
patch on the `status` subresource: `test` `/metadata/uid` and `/metadata/resourceVersion`, then add (or replace at its
index) the condition `{"type":"Issuing","status":"True","reason":"ManuallyTriggered",…}`.
