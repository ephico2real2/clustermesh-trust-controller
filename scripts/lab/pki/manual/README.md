# Manual mesh PKI with openssl

Use these scripts to create the mesh PKI by hand, without cert-manager making the root. The result has the same
names and lifetimes as the cert-manager path ([MESH_PKI.md](../../../../MESH_PKI.md), ADR-011). cert-manager still
signs the leaves: each cluster gets its intermediates as Secrets, and a CA ClusterIssuer signs from each one.

When to use it:

- a new mesh whose root key must stay offline, which is the usual practice in production;
- recovery, when the cluster that holds the root is lost.

Status: **tested** on 2026-10-26 (OpenSSL 4.0.3 and LibreSSL 3.3.6, and one import on kind-cmtc-a with a test cluster
name that was removed afterwards). **Not used on the labs**: the labs' root was made by cert-manager
(`scripts/lab/pki/mesh-pki.sh`).

## How it differs from mesh-pki.sh

| | `mesh-pki.sh` | These scripts |
|---|---|---|
| Root key | made by cert-manager in the control cluster, then copied to every cluster | made by openssl, kept offline, never in a cluster |
| Intermediates | made by cert-manager in each cluster | made by openssl, then imported |
| Intermediate renewal | automatic | by hand: run steps 2 and 3 again with a new directory, before the 3 years end |
| Leaves (ClusterMesh, ztunnel, SPIRE's CA) | cert-manager | cert-manager, unchanged |

Do not use both paths for the same name. A cert-manager Certificate of the same name would overwrite the imported
Secret at its next renewal, so `install-intermediate.sh` refuses when one exists.

## Files

| File | What it does |
|---|---|
| `ca.cnf` | The certificate extensions: the root has no path length limit, the ClusterMesh intermediate allows no CA below it (`pathlen:0`), the SPIRE intermediate allows one (`pathlen:1`, for SPIRE's own CA). |
| `make-root.sh DIR [PREFIX]` | Makes `DIR/root.key` and `DIR/root.crt`: ECDSA P-256, 10 years, `CN=<PREFIX> mesh root CA` (default `cmtc`). |
| `make-intermediate.sh DIR CLUSTER KIND` | Makes `DIR/<CLUSTER>-<KIND>-intermediate.key` and `.crt`, signed by the root: ECDSA P-256, 3 years. KIND is `clustermesh` or `spire`. |
| `install-intermediate.sh DIR CONTEXT CLUSTER KIND` | Imports one intermediate into a cluster: Secret `cert-manager/<CLUSTER>-<KIND>-intermediate` (`tls.crt`, `tls.key`, `ca.crt` = the root) and a ClusterIssuer of the same name. |

Every script refuses to replace a file or a Secret that already exists, and leaves no partial files after a failure.
No script prints a private key.

## Prerequisites

- `openssl` (OpenSSL 3 or later, or LibreSSL 3.3 or later) and `kubectl`.
- cert-manager running in each cluster, in namespace `cert-manager`.
- A directory **outside the repository** for the keys, for example on an encrypted disk. Never commit it.

## Steps

1. Make the root, once for the whole mesh:

   ```sh
   bash scripts/lab/pki/manual/make-root.sh /secure/cmtc-pki
   ```

   Expected: `subject=CN=cmtc mesh root CA`, an end date 10 years away, and the SHA-256 fingerprint. Record the
   fingerprint: every verifier pins it.

2. Make the two intermediates of each cluster:

   ```sh
   bash scripts/lab/pki/manual/make-intermediate.sh /secure/cmtc-pki cmtc-a clustermesh
   bash scripts/lab/pki/manual/make-intermediate.sh /secure/cmtc-pki cmtc-a spire
   ```

   Expected: `…intermediate.crt: OK` and `issuer=CN=cmtc mesh root CA`. Repeat for cmtc-b.

3. Import them into each cluster:

   ```sh
   bash scripts/lab/pki/manual/install-intermediate.sh /secure/cmtc-pki kind-cmtc-a cmtc-a clustermesh
   bash scripts/lab/pki/manual/install-intermediate.sh /secure/cmtc-pki kind-cmtc-a cmtc-a spire
   ```

   Expected: `secret/… created`, `clusterissuer… created` and `condition met`. Repeat for cmtc-b with its context.

4. Give the root certificate (`root.crt`, never `root.key`) to the verifiers: Cilium's `tls.caBundle`, and
   trust-manager's ConfigMap `cmtc-mesh-root`, which reads `ca.crt` from the SPIRE intermediate Secret.

5. Check one cluster:

   ```sh
   kubectl --context kind-cmtc-a get clusterissuer cmtc-a-clustermesh-intermediate cmtc-a-spire-intermediate
   kubectl --context kind-cmtc-a -n cert-manager get secret cmtc-a-spire-intermediate -o jsonpath='{.data.ca\.crt}' \
     | base64 -d | openssl x509 -noout -subject -fingerprint -sha256
   ```

   Expected: both issuers `READY True`; the subject `CN=cmtc mesh root CA` and the fingerprint from step 1.

## Open

- The CMTC chart creates `<cluster>-spire-intermediate` with cert-manager when `trust.enabled` is true. A chart option
  to use an imported intermediate instead is not written yet.
- `scripts/lab/up.sh` uses `mesh-pki.sh` only.
