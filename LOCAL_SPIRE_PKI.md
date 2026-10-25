# Local SPIRE PKI preparation

CMTC uses this certificate hierarchy:

Organization root → cluster CA → exact SPIRE CA → workload SVID.

The organization root key stays on the MacBook in a private directory outside this repository.
Each cluster creates its own cluster CA key inside Kubernetes.
SPIRE creates its own signing key.
Public certificates move between these components. Private keys do not move with the evidence.

## Preserve ClusterMesh

The current ClusterMesh issuer is `cmtc-lab-intermediate`.
Its Secret is `cert-manager/cluster-intermediate`.
Its certificates do not allow the extra SPIRE CA level.
Keep that issuer and Secret intact.

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

The complete ARM64 race suite passes73 top-level tests and204 subtests.
The initializer also passes10 repetitions:180 top-level invocations and320 subtest invocations.
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

SPIRE 1.15.5 now runs in `cilium-spire` on both clusters.
Each server uses a retained PVC for its database and disk KeyManager.
All four node agents pass PSAT attestation with their actual Pod UID and Node UID.
Registration uses bounded retries, exact selector confirmation and an explicit readiness acknowledgment.

The renderer is [render_spire.py](scripts/lab/spire/render_spire.py).
The active-key check is [public_proof.py](scripts/lab/spire/public_proof.py).
The check creates a fresh nonce identity and asks the running server to mint a short-lived certificate.
Only its public certificate leaves the Pod.
The check verifies the direct signer, approved cluster parent and organization root.
This administrator check proves active signing-key possession. It does not prove workload attestation.

Both clusters pass the nonce check before and after a real server restart.
However, the restart test fails signing-authority retention.
The servers recover the same PVCs and databases but select new direct signers.
Cert-manager returns RFC7093 SHA256 subject-key identifiers; non-FIPS SPIRE uses SHA1 to find its CA journal.
The identifiers differ for the same public key.
The disk key path is correct.
Do not delete keys, journals or PVCs to bypass this failure.

The native recovery fix starts from current upstream in [the SPIRE fork](https://github.com/ephico2real2/spire).
It remains under local qualification.
The issuer producer stays disabled until the exact fix image passes retained-signer recovery.
[Public deployment logs, nonce proofs and the failed assertion](docs/evidence/spire-runtime/summary.json) are retained.
The existing 36 application paths still pass on TCP ports 80, 8080 and 31337.
These are reachability checks, not mTLS evidence.

## Remaining gates

This increment prepares the cluster CA. It does not install or activate workload mTLS.
SPIRE still needs a passing retained-signer restart test with the exact fix image.
Workload registration and the real issuer producer are not active yet.
A bundle's first certificate is not sufficient evidence.

Native remote identity, effective policy, durable admission and connection recovery remain required.
Keep the combined ClusterMesh/ztunnel guard closed until those tests pass.

## Live API correction

The first real initialization Job passed. The completion Job exposed a missing fake-API rule: Secret type is immutable.
The helper now keeps the Secret Opaque and adds the public certificate in place.
The regression fixture enforces type immutability. Permanent API rejections return after one attempt.
Transient failures still use bounded retries and confirmation.
[The original failure and structured logs](docs/evidence/spire-ca-initializer/initial-real-api-failure.json) are retained.
The host root, cluster key, pending CSR and public approval were preserved for the corrected retry.
Temporary Jobs and permissions were removed. Cilium and ClusterMesh configuration stayed intact.

The host orchestrator is [pki.py](scripts/lab/pki/pki.py).
Its20 local tests pass with real OpenSSL cryptography and API fault fixtures.
It uses a private UNIX proxy and server-side metadata-only Secret reads.
It records exact cluster/node/image pins, retains public Job logs and waits for conditional cleanup.
