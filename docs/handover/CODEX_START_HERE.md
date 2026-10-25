# Continue CMTC implementation

The active mandate is end-to-end CMTC security delivery. Questions and documentation requests steer that work. They do not complete or cancel it.

## Read in this order

1. Read [README](../../README.md).
2. Read [delivery status](../agile/DELIVERY_STATUS.md).
3. Read [the backlog](../agile/BACKLOG.md).
4. Read [the security test matrix](../architecture/SECURITY_AND_FAILURE_TEST_MATRIX.md).
5. Read [the local Podman workflow](../development/PODMAN_LOCAL_VALIDATION.md).
6. Read [the registration design change](../../SPIRE_REGISTRATION_DESIGN.md).
7. Read [the illustrated PKI flow](../../PKI_TRUST_FLOW.md).
8. Read [the image build steps](../../LOCAL_IMAGE_BUILD.md).
9. Read [the documentation guide](../../DOCUMENTATION_GUIDE.md).

## Current runtime

Use `cmtc-a` and `cmtc-b` in the existing Colima `cmtc-cilium` runtime. Keep ClusterMesh and KVStoreMesh enabled. Preserve applications, signers, PVCs, image pins and port forwards.

The CMTC Observe processes and issuer-profile producer run in both clusters. SPIRE servers and node agents issue verified workload SVIDs through the qualified native path. Ztunnel remains disabled. Cross-cluster workload mTLS is incomplete.

The experimental registrar is a separate CMTC Go image inside the SPIRE server Pod. Its permanent ownership is undecided. The original plan reused Cilium enrollment. Do not describe this helper as the node DaemonSet.

## Current source work

The Cilium fork has source-qualified source-IP receipts and native policy-drain guards. These are separate from the older deployed image. Use delivery status for exact pins.

The registrar trial found a real ztunnel client defect. The client swallowed SPIRE stream errors and later reported a deadline. The corrected source passed 568 full-profile tests plus two diagnostic cases, format and strict Clippy. Its exact diagnostic image is imported and version-verified on all four nodes. The corrected withdrawal fixture passes in both clusters with authorized controls, recovery and exact cleanup. The final 36-path application check also passes. Production integration remains open. Keep target credential absence distinct from delegate denial in future tests.

The restore path still lacks complete persistent quarantine before regeneration. Kernel policy-map reachability, mandatory capture and active transport-grant closure remain open. Keep the ClusterMesh/ztunnel guard closed.

## Documentation preference

Use diagram-kit for the SPIRE registration workflow guide. Generate only light-theme image files for that guide. Do not create temporary dark renders. Documentation displays light-theme figures. Preserve existing dark evidence and the separate Grafana both-theme checks.

## Local workflow

1. Check the checkout, branch, SHA and dirty files.
2. Read the actual failure log.
3. Review the proposed fix.
4. Run meaningful local tests.
5. Run required lint and vet.
6. Build with host Podman for Linux ARM64.
7. Import the archive into the existing runtime.
8. Verify the actual running image and source.
9. Run positive, negative and recovery checks.
10. Save evidence.
11. Commit the qualified increment.
12. Continue to the next dependency.

The user authorized feature-branch pushes on 2026-10-25. Keep local qualification first. Manual CI dispatch and registry image publication remain deferred. Agent reports do not establish correctness. The primary agent must review and test their code.

## Approval boundary

Automatic approval review rejected the persistent node-agent Admin group-permission change. The explicit four-node question remains pending. Do not apply that migration without the answer. The registrar's server-only directory restriction is a different change.

## Historical notes

[Earlier handover history](HISTORY_TO_2026-10-24.md) preserves the original records. Old references to `cmtc-mtls` describe removed fixtures. Do not recreate that cluster for normal testing.
