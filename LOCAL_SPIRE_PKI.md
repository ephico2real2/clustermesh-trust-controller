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
The new SPIRE issuer will be `cmtc-spire-issuer`.
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
It changes the same Secret to `kubernetes.io/tls` with both required fields in one update.
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

The complete ARM64 race suite passes72 top-level tests and204 subtests.
The initializer also passes10 repetitions:170 top-level invocations and320 subtest invocations.
Formatting and vet pass. No selected test fails or is skipped.
[The source ledger and raw results](docs/evidence/spire-ca-initializer/summary.json) retain the evidence.

Tests cover concurrent initialization, lost write acknowledgments, retry bounds, structured logs, UID replacement and malformed approvals.
They also reject wrong roots, wrong keys, CSR attributes and certificate-chain substitution.
Cancellation after a successful confirmation returns no acknowledgment.
The next invocation must reuse the existing key and CSR.

A fake API does not prove Kubernetes Secret typing, effective RBAC or actual Job execution.
The next step is the host-Podman image build and exact-image Job test on both clusters.

## Remaining gates

This increment prepares the cluster CA. It does not install or activate workload mTLS.
SPIRE needs durable server storage, node attestation, bounded registration and real readiness checks.
Its active signer must be verified from actual issuance and a running-server key proof.
A bundle's first certificate is not sufficient evidence.

Native remote identity, effective policy, durable admission and connection recovery remain required.
Keep the combined ClusterMesh/ztunnel guard closed until those tests pass.
