# Local SPIRE PKI preparation

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](docs/agile/DELIVERY_STATUS.md) and [documentation terms](DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

**Current state (read 2026-10-25T23:07Z):** both SPIRE servers run
`localhost/cmtc-spire-server@sha256:f57e537d42e5a8cc94fbae110b4f67a70481f391fef70171143d9a1b81cf0288`, the same digest
this guide qualified below (source `28f6b8d84a`). The SPIRE node agents have since moved to
`localhost/cmtc-spire-agent:delegated-0f8fe4d681`. The qualification results below are **historical** (2026-10-24).
Exact pins are in [delivery status](docs/agile/DELIVERY_STATUS.md).

CMTC uses this certificate hierarchy:

Organization root → cluster CA → exact SPIRE CA → workload SVID.

The organization root key stays on the MacBook in a private directory outside this repository.
Each cluster creates its own cluster CA key inside Kubernetes.
SPIRE creates its own signing key.
Public certificates move between these components. Private keys do not move with the evidence.

Read [the illustrated PKI flow](PKI_TRUST_FLOW.md) for issuance and verification. Read [the image build steps](LOCAL_IMAGE_BUILD.md) before reproducing the helper or SPIRE builds.

## Preserve ClusterMesh

Historical, until 2026-10-26: the ClusterMesh issuer was `cmtc-lab-intermediate` on Secret `cert-manager/cluster-intermediate`, whose certificates did not allow the extra SPIRE CA level.
ClusterMesh now uses `<cluster>-clustermesh-intermediate` from the mesh root ([MESH_PKI.md](MESH_PKI.md)); SPIRE's move onto `<cluster>-spire-intermediate` is proposed.

The new SPIRE cluster CA uses `cert-manager/cmtc-spire-cluster-ca`.
The new SPIRE issuer is `cmtc-spire-issuer`.
Only the existing `cmtc-a` and `cmtc-b` clusters are used.
Installing this dependency must preserve the Cilium images, networking and encryption settings.

## In-cluster initialization

The administrator creates an empty, owned Opaque Secret.
The initializer pins its UID, cluster name and organization-root fingerprint.
The initializer creates one key and one public CSR.
A retry confirms the stored key and returns the same CSR.

The host signs the public CSR.
The host puts the public certificate chain in an immutable approval ConfigMap.
The completer pins that ConfigMap's UID.
It validates the CSR, cluster, Secret UID, pending resourceVersion, certificate key, root and path depth.
It adds the verified certificate to the same Opaque Secret.
Kubernetes Secret types are immutable. The helper preserves the original type, key and UID.
It confirms the committed state before it returns a public acknowledgment.

The Job service account needs `get` and `update` on that exact Secret.
It needs `get` on the exact public approval ConfigMap.
The normal CMTC controller and node agents do not receive Secret access.
The host does not fetch or patch the populated Secret.

The implementation is [cluster_ca.go](cmd/lab-identity-init/cluster_ca.go).
`LAB_INIT_MODE=cluster-ca-init` initializes the key and CSR.
`LAB_INIT_MODE=cluster-ca-complete` installs the approved certificate.
Explicit cluster, Secret UID and root pins are required.
The legacy lab path is retained. It is not used for this SPIRE installation.

## Local validation

The complete ARM64 race suite passes 73 top-level tests and 204 subtests.
The initializer also passes 10 repetitions: 180 top-level invocations and 320 subtest invocations.
Formatting and vet pass. No selected test fails or is skipped.
[The source ledger and raw results](docs/evidence/spire-ca-initializer/opaque-correction-summary.json) retain the evidence.

Tests cover concurrent initialization, lost write acknowledgments, retry bounds, structured logs, UID replacement and malformed approvals.
They also reject wrong roots, wrong keys, CSR attributes and certificate-chain substitution.
Cancellation after a successful confirmation returns no acknowledgment.
The next invocation must reuse the existing key and CSR.

A fake API does not prove Kubernetes Secret typing, effective RBAC or actual Job execution.
The corrected ARM64 image was built with host Podman and loaded into all four nodes.
Actual initializer and completion Jobs passed on both clusters.
The cmtc-a retry preserved its existing key, CSR, Secret UID and public approval.
Both runs confirmed unchanged Cilium, node and cert-manager snapshots and removed all temporary permissions and Jobs.
Both separate `cmtc-spire-issuer` ClusterIssuers are Ready.
[The exact image, public Job logs and cluster pins](docs/evidence/spire-ca-initializer/real-clusters/summary.json) are retained.

## SPIRE deployment and recovery test

SPIRE server source `28f6b8d84ade21c6accb32ba9689a3bdf64877ec` runs in `cilium-spire` on both clusters.
It starts directly from current upstream `main` at `0d589ad07d7b7e7a244f5b5548bf9d2d21e9fbba` in [the personal SPIRE fork](https://github.com/ephico2real2/spire).
The local branch is `fix/ca-journal-subject-key-id`. No branch or image was published.

The original 1.15.5 restart test exposed a real CA journal lookup failure.
Cert-manager uses an RFC7093 SHA256 subject-key identifier; non-FIPS SPIRE uses SHA1 for its native lookup.
The fix checks the supported identifiers and rejects an ambiguous fallback.
Fallback recovery also verifies the exact CA, signing key and upstream authority.
[The original failed test](docs/evidence/spire-runtime/summary.json) remains historical evidence.
[The recovery source patch and evidence](docs/evidence/spire-recovery/summary.json) record the correction.

The exact ARM64 image is `localhost/cmtc-spire-server@sha256:f57e537d42e5a8cc94fbae110b4f67a70481f391fef70171143d9a1b81cf0288`.
Its configuration ID is `sha256:70f8fbde787b46479d8bd22aed9005d36caa7c597fcff7108cee9bf122a6edd0`.
The server reports `1.16.0-dev-28f6b8d84ade21c6accb32ba9689a3bdf64877ec`.
At this record the node agents ran the same fork source; they now run `0f8fe4d681`. [The node API guide](LOCAL_SPIRE_WORKLOAD_API.md) records their earlier image and secure kubelet configuration.

Host Podman builds a static ARM64 server with the pinned musl builder.
[The build script](docs/evidence/spire-recovery/build-server.sh) records the toolchain, base image, explicit platform, resource limits and source label.
The archive is imported into the existing Colima kind nodes.
The importer verifies the actual containerd manifest, configuration, architecture and binary on all four nodes.
It creates a canonical manifest reference without replacing an existing tag.
The synthetic CRI archive digest is not a usable pull reference.
Both worker image-volume CLI checks pass with the canonical reference.

Before upgrade, each server stops and takes a private database/key backup inside its existing PVC.
The backup stays in `.cmtc-preupgrade-28f6b8d84a/` with directory mode 0700 and archive mode 0600.
The archive audit checks exact regular files and copy equivalence. No backup or key leaves the PVC.
SQLite migration tests cover the actual schema 25→27 transition.
Do not start the old binary on the migrated database as an automatic rollback.

Both servers pass two real restart rounds with the same signer and PVC UID.
All four agents then pass fresh PSAT attestation with new Pod UIDs and the independently pinned Node UIDs.
The public nonce check also proves possession of each exact retained signing key and its approved chain.
This administrator check is not workload attestation.
The new server's source version appears in the raw restart log; early per-round version files are empty because the CLI writes to stderr.

Local ARM64 race tests pass 89 top-level tests and 96 subtests.
SQLite migration tests pass 4 top-level tests and 29 subtests.
Vet passes. Change-only lint reports 0 issues.
The first broad lint run retains one warning in unchanged upstream `manager_test.go:620`.
No selected test fails or is skipped.

## Gates after this record

The issuer-profile producer is enabled in both clusters ([its guide](LOCAL_ISSUER_PROFILE.md),
[live ledger](docs/evidence/live-issuer-publication/summary.json)). Native credential delivery has separate passing
evidence ([credential guide](LOCAL_NATIVE_CREDENTIALS.md)). Ztunnel now runs in both clusters and the Cilium
ClusterMesh/ztunnel guard was replaced by capability validation (`37d5fce0f7`).
A public bundle, node readiness or publication ACK is not evidence of workload protection.
Recovery on the current images and per-connection peer-certificate evidence remain open; read
[delivery status](docs/agile/DELIVERY_STATUS.md).

## Live API correction

The first real initialization Job passed. The completion Job exposed a missing fake-API rule: Secret type is immutable.
The helper now keeps the Secret Opaque and adds the public certificate in place.
The regression fixture enforces type immutability. Permanent API rejections return after one attempt.
Transient failures still use bounded retries and confirmation.
[The original failure and structured logs](docs/evidence/spire-ca-initializer/initial-real-api-failure.json) are retained.
The host root, cluster key, pending CSR and public approval were preserved for the corrected retry.
Temporary Jobs and permissions were removed. Cilium and ClusterMesh configuration stayed intact.

The host orchestrator is [pki.py](scripts/lab/pki/pki.py).
Its 20 local tests pass with real OpenSSL cryptography and API fault fixtures.
It uses a private UNIX proxy and server-side metadata-only Secret reads.
It records exact cluster/node/image pins, retains public Job logs and waits for conditional cleanup.
