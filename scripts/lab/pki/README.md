# Owned SPIRE cluster-parent PKI orchestrator

<!-- CMTC_DOC_CONTEXT -->
Guide scope: check current runtime and feature gates before using these instructions. Read [current delivery status](../../../docs/agile/DELIVERY_STATUS.md) and [documentation terms](../../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

`pki.py` needs Python 3.11+ with cryptography>=44, host OpenSSL 3, kubectl,
Colima and Docker inside the retained cmtc-cilium VM. The repository `venv` does
not provide cryptography (checked 2026-10-25); use an interpreter that does.

**Current state (read 2026-10-25T23:13Z):** this helper ran once per cluster on
2026-10-24 ([LOCAL_SPIRE_PKI.md](../../../LOCAL_SPIRE_PKI.md)). Both SPIRE
servers still run the image that guide qualified. The helper refuses to rotate
an existing cluster certificate (see "Kubernetes ownership and recovery").

This increment issues the isolated cluster-parent certificate. It does not
install SPIRE, select a workload signer by bundle order, publish issuer profiles,
activate ztunnel, change Cilium, establish federation, or claim workload mTLS.
Use the separately reviewed standalone SPIRE manifests after this step. Existing
cert-manager is required and is never installed/upgraded by this helper.

## Inputs and invocation

The image must contain the reviewed `/lab-identity-init` binary, including the
primary's cancellation-before-public-ACK correction. Build/load it locally first.
Supply independent full config/source/manifest pins from its build ledger. The
helper confirms the running Pod manifest and actual node CRI config+OCI revision.
The Kubernetes API is selected explicitly through kind-cmtc-a or kind-cmtc-b;
only the retained two-node clusters are supported.

Create an empty host directory outside the repository/evidence tree, mode 0700,
using its canonical absolute path. Symlink path components are rejected (on macOS
use `/private/var/...`, not `/var/...`). The helper never removes this directory.
The organizational P256 key and self-signed pathLen2 root are an atomic directory
pair, private 0600 files behind an exclusive lock. Unknown/partial root state is
refused. Visible committed files are re-fsynced before reuse. Host root private
key material is never sent to Kubernetes, printed, or included in evidence.
The root key is read through held FDs by OpenSSL; a held private directory and
nonblocking/no-follow file checks reject FIFOs, symlinks and unsafe ownership.
As with any local key tool, same-UID/root compromise is outside this boundary.

Example, replacing every independent pin with the actual build/cluster ledger:

```sh
python3 pki.py \
  --kubeconfig /private/tmp/cmtc-a-b-20261024.kubeconfig \
  --cluster cmtc-a --expected-cluster-uid ACTUAL_KUBE_SYSTEM_UID \
  --expected-node cmtc-a-control-plane=ACTUAL_NODE_UID \
  --expected-node cmtc-a-worker=ACTUAL_NODE_UID \
  --root-directory /Users/olasumbo/.local/share/cmtc-pki \
  --repository-root /Users/olasumbo/gitRepos/clustermest-trust-controller \
  --image localhost/cmtc:QUALIFIED_SOURCE_TAG \
  --image-config sha256:FULL64HEX --image-manifest sha256:FULL64HEX \
  --source-revision FULL40HEX
```

Run cmtc-b separately with its independent namespace/node UID pins and the SAME
external root directory. The root lock prevents concurrent signing. Each request
gets a distinct random serial; each cluster key is created inside its cluster.
No current-context mutation is used. Cilium DaemonSet/config, cert-manager spec,
node UIDs and the kubeconfig current-context value are compared before/after.

## Kubernetes ownership and recovery

Public persistent ledger: `cert-manager/cmtc-spire-cluster-ca-ledger`.
Private persistent key/certificate: `cert-manager/cmtc-spire-cluster-ca`.
Immutable public approval: `cert-manager/cmtc-spire-cluster-ca-approval`.
No other authority Secret is read or modified. An existing Secret without its
ledger is refused; matching labels are not sufficient adoption authority.

The only host Secret creation is empty Opaque. The response must be empty.
Every later host Secret ownership read uses server-side PartialObjectMetadata
with NO JSON fallback. No host Secret GET/list/update/export is permitted by the
transport. Initializer/completer Jobs receive only exact Secret UID, root pin,
cluster name, and immutable approval UID. All key reads/updates remain in-cluster.
The temporary Job SA's Role grants only exact Secret get/update and approval CM
get. Effective positive/negative RBAC is tested through impersonated auth can-i;
normal CMTC controller/DaemonSet accounts are unchanged.

The ledger records the created Secret UID before any key-generating Job starts.
An ambiguous Secret-create-to-ledger window is deliberately NOT auto-adopted:
if the Secret exists but its UID was not committed, preserve it and request
explicit administrator recovery. Likewise approval creation precedes storing
its UID; an unrecorded existing approval is refused. Administrator recovery must
inspect metadata/public state and explicitly repair the owned ledger using its
UID/RV; this tool does not read an existing private key to reconstruct authority.
Retries with a committed UID reuse the reviewed initializer's stable CSR/key.
Already-completed Opaque certificate state is accepted only through the exact immutable public
approval and completer. Existing certificate rotation is deliberately refused.

Temporary Job/SA/Role/RoleBinding objects have unique names and recorded UIDs.
Deletion includes current UID AND resourceVersion preconditions. Replacement
objects are preserved. Unknown creation outcomes are reported as leftovers and
not deleted/adopted. Persistent CA, ledger and approval are NEVER deleted during
failure cleanup. Cleanup polls the exact recorded UID to absence with a bounded deadline after
foreground deletion. A timeout or replacement is reported as a leftover and
makes the run fail; accepted DELETE alone cannot report successful cleanup.
Reviewed public Job logs, including failed Job retry diagnostics, are bounded
and retained in the report. Private-key markers cause refusal and content is
withheld. No raw Secret or private log body is written to evidence.
No PVC is created/deleted: preserve the standalone SPIRE datastore PVC separately.

## Exact active SPIRE issuer source

`derive_spire_candidate()` reads a public cert-manager CertificateRequest with
exact expected UID, requester service account, issuerRef, Ready+Approved status,
CSR signature and key, exact trust-domain URI SAN, current pathLen0 or unconstrained SPIRE CA, and exact
approved parent/root signatures. It reobserves UID/RV before returning.
It returns `qualified:false` and an explicit missing running-key-proof gate.
No certificate is selected by upstream bundle order. The organizational root or
cluster-parent certificate is never treated as the SPIRE direct workload signer.
An unconstrained SPIRE CA is still an EXACT direct workload signer: the local
qualification helper rejects leaves issued by any delegated child, parent or root.
The primary must prove the RUNNING SPIRE server holds the direct-signer key
before constructing an approved issuer profile. This extraction helper never
publishes a profile or accepts a passed hash string as that proof.

## Tests and remaining execution gates

Executed locally on 2026-10-24: 20 top-level unittest cases, all pass, no skips. Tests use a
real OpenSSL executable and real ephemeral P256 keys; fake API implements UID/RV
CAS and checks metadata-only Secret requests. They cover root/signing identity,
separate cluster parents, pathLen2/1, stable reuse, root partial/symlink/mode/key
mismatch/lock/path replacement, CSR digest/subject/pin rejection, existing-Secret
nonadoption, lost ledger update, missing/replaced authority, public-only logs,
immutable approval UID persistence/replay, exact UID/RV deletion, unknown create
leftovers and public CertificateRequest identity/lineage/reobservation rejection.

```sh
# From scripts/lab/pki, with a Python that has cryptography>=44:
python3 -m unittest -v test_pki
```

The primary qualified actual cluster-parent Jobs on both clusters with exact
image/source checks. See the root LOCAL_SPIRE_PKI.md guide. SPIRE deployment
and runtime signer proof remain separate. Qualification includes the actual
metadata content negotiation (406 must refuse), CRI labels/config identity,
Secret real-API typing, Job RBAC/logs, helper stdout contract and cleanup absence.
Fake tests cannot establish these properties. Root initialization fsync/rename
logic is exercised normally; SIGKILL/power-loss fault injection is still a
separate acceptance gate. Do not infer durable server storage or actual
workload mTLS from successful cluster-parent issuance.
