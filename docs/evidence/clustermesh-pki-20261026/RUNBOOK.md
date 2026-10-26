# Move ClusterMesh onto the cert-manager mesh root (2026-10-26)

**Status: proposed.** Manifests validated by server-side dry run on both clusters; nothing applied. Design:
[ADR-011](../../architecture/adr/ADR-011.md).

## Why

The ClusterMesh intermediates from `scripts/lab/up.sh` expire on 2026-10-26 at 19:37:39Z (cmtc-a) and 19:37:43Z
(cmtc-b), and their root key was deleted by design (`up.sh:117`). Every step below must finish before 19:37Z.

## Trust inputs and issued certificates

Every ClusterMesh verifier reads `kube-system/cmtc-public-root` key `ca.crt`. That covers the Cilium agent
(`common-etcd-client-ca.crt`, `ztunnel-origin/ca.crt`, `ztunnel-membership/ca.crt`), KVStoreMesh, and the
clustermesh-apiserver (`etcd-server-secrets/ca.crt`, `etcd-admin-client/ca.crt`). ClusterIssuer
`cmtc-lab-intermediate` issues all 7 Certificates in `kube-system`: the 4 clustermesh-apiserver certificates,
`cmtc-ztunnel-ads-server`, `ztunnel-membership-writer` and `ztunnel-origin-reader`.

## Reload behavior (source-checked, Codex review 2026-10-26)

| Verifier or server | Reloads `ca.crt` or its own certificate? | Source |
|---|---|---|
| clustermesh-apiserver etcd server | Client CA pool loaded once; its own leaf reloads per handshake | vendored `etcd/client/pkg/v3/transport/listener.go:472,529` |
| Cilium agent and KVStoreMesh etcd clients | Root pool loaded at client construction; the watcher ignores CA-only changes | `pkg/kvstore/etcd.go:429`, `pkg/clustermesh/common/config.go:226` |
| Direct-origin client | Reloads: hashes CA, certificate and key every 2 s and rebuilds the client | `pkg/ztunnel/remote_workload/origin_supervisor.go:163,876` |
| Cilium agent ADS server (`127.0.0.1:15012`) | Its certificate is loaded once, at `Serve()` | `pkg/ztunnel/ca/ca_server.go:77-78`, `pkg/ztunnel/xds/xds_server.go:103` |
| ztunnel ADS client | Reads `/etc/ztunnel/bootstrap-ca.crt` (from `cmtc-public-root`) on every reconnect | ztunnel `src/xds/client.rs:813`, `src/tls/control.rs:42` |

A restart of the clustermesh-apiserver Deployment rebuilds its etcd store. Both clusters run `etcd-init` with
`--etcd-create-ztunnel-membership-users=true` (read 2026-10-26), so the ztunnel users are recreated.

**Second deadline.** Every agent serves the ADS certificate it loaded at its 04:10-04:45Z restart. That certificate
expires at 15:50:45Z (cmtc-a) and 15:50:47Z (cmtc-b). After that, any new ztunnel ADS connection fails, including
the resync of every issuer generation. The agent restarts in step 7 must therefore finish before 15:50Z.

## Procedure

Use the explicit context `kind-<cluster>`. Record every write in `operations.log`. Stop at the first failed check.
Run the traffic join after each numbered step. Run steps 1-8 between 13:00Z and 14:40Z: no scheduled renewal falls
in that window (the next ones are 14:46Z, 14:50Z and 19:37Z), so cert-manager issues nothing the runbook did not ask
for. Complete each step on both clusters before starting the next.

0. **Preflight and record** for each of the 7 Certificates: generation, revision, `Ready` with `observedGeneration`
   equal to `metadata.generation`, `Issuing` not True, no `status.nextPrivateKeySecretName`, no pending
   CertificateRequest, renewal time, and the full SPKI of the issued key. Record the root fingerprints in every
   projected `ca.crt`.
1. **Mint the root on cmtc-a.** Apply [01-root-control-cmtc-a.yaml](manifests/01-root-control-cmtc-a.yaml). Check:
   `cmtc-mesh-root-ca` is Ready; the certificate is self-signed, `CA:TRUE`, valid 10 years.
2. **Copy the root Secret to cmtc-b.** Stream, without printing or storing, `kubectl --context kind-cmtc-a -n
   cert-manager get secret cmtc-mesh-root-ca -o json | jq '{apiVersion:"v1",kind:"Secret",metadata:{name:"cmtc-mesh-root-ca",namespace:"cert-manager"},type:.type,data:.data}' | kubectl --context kind-cmtc-b create -f -`.
   No UID, resourceVersion or owner references are copied. Check: the `tls.crt` SHA-256 is equal on both clusters.
3. **Issue each cluster's intermediate.** Apply [02-cluster-issuers.yaml](manifests/02-cluster-issuers.yaml) with
   `CLUSTER_NAME` replaced. Check: `cmtc-mesh-root` and `cmtc-clustermesh-intermediate` are Ready, and the
   intermediate verifies against the root.
4. **Bundle overlap.** Patch `cmtc-public-root` `ca.crt` to the disposable root followed by the mesh root, with a
   JSON-patch `test` on uid, resourceVersion and the old value. Check: both root fingerprints appear in the projected
   `ca.crt` of every Cilium agent, every ztunnel (`/etc/ztunnel/bootstrap-ca.crt`) and the clustermesh-apiserver Pod.
5. **Keep the server key.** Merge-patch `clustermesh-apiserver-server-cert` `spec.privateKey.rotationPolicy: Never`.
   Re-run the step-0 preflight for it.
6. **Switch the issuer and reissue the ADS certificate.** Patch ClusterIssuer `cmtc-lab-intermediate`
   `spec.ca.secretName` from `cluster-intermediate` to `cmtc-clustermesh-intermediate`. Check: `Ready=True` with
   `observedGeneration == metadata.generation`. Then reissue `cmtc-ztunnel-ads-server` (patch below). Its only verifier,
   ztunnel, already trusts both roots and rereads the file on reconnect.
7. **Reload the verifiers.** Restart the clustermesh-apiserver Deployment, then each Cilium agent, one node at a time.
   This loads the two-root pools and the new ADS certificate together. Check per node: the certificate served on
   `127.0.0.1:15012` chains to the mesh root; the ztunnel ADS stream is up; the direct origin reconnected (peer count
   4); the membership users exist and membership leases are repopulated. Finish before 15:50Z.
8. **Reissue the other 6 Certificates,** one at a time (patch below). Check after each: revision +1, `tls.crt` chains
   to the mesh root, and for the server Certificate the SPKI in the Secret and on a fresh connection is unchanged
   (cmtc-a `d1a0d97f…3214`, cmtc-b `0822f405…8199`). The clients' own keys reload per handshake.
9. **Persist.** The server-only chart value exists only in the fork commit `64a07d46a6`, which is not deployed. Until
   it is, the live `rotationPolicy: Never` patch is the control, and no `helm upgrade` may run. Write
   `tls.caBundle.content` (both roots) into the release values with that Helm change.
10. **Retire the disposable root** before 2026-10-27T19:37Z: inventory every consumer of `cmtc-public-root`
    (including the operator and Hubble, if enabled); persist and apply the mesh-root-only bundle; restart as in step 7;
    check that an old-only chain is refused and traffic passes.

**Reissue patch** (JSON patch on `/apis/cert-manager.io/v1/namespaces/kube-system/certificates/<name>/status`), built
from a fresh read: `test` `/metadata/uid` and `/metadata/resourceVersion`, then `add` to `/status/conditions/-`
`{"type":"Issuing","status":"True","observedGeneration":<generation>,"lastTransitionTime":"<now>","reason":"ManuallyTriggered","message":"Certificate re-issuance manually triggered"}`.
If an `Issuing` condition already exists, replace that entry at its index instead of appending.
