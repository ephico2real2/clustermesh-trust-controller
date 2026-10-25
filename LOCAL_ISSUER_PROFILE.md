# Local issuer-profile qualification

The issuer-profile producer is enabled on both existing mesh clusters.
It publishes verified mappings from the real SPIRE signing authorities.
Both clusters pass renewal, restricted RBAC, structured logging and five live metric queries.
The controller image remains the qualified `f5fe9992da` image below.
CMTC remains in Observe mode. Workload mTLS is not enabled.

[The live publication ledger](docs/evidence/live-issuer-publication/summary.json) records the exact resource UIDs, image pins and renewal sequences.
Generation1 approval expires at `2026-10-26T03:55:11Z`.
Rotate the immutable approval before expiry. Do not extend it by resetting the ledger or version floors.
The mutable publication has a lease of at most30 seconds.
A publication acknowledgment does not prove native consumer acceptance or traffic protection.

The earlier direct-root and approved-parent trials restored their templates and removed their trial resources.
The current activation is persistent. Preserve its source, output, RBAC and private host ownership ledger at `~/.local/share/cmtc-issuer-profile/live-a-b/`.
The ledger contains public proof and ownership state. It does not contain CA private keys.

## Persistent activation helper

Use [publish_issuers.py](scripts/lab/issuer-profile/publish_issuers.py) for the persistent activation.
It pins both cluster UIDs, controller UIDs, node UIDs, cluster-parent approval UIDs and the root fingerprint.
It obtains fresh nonce proofs from both exact SPIRE server images before each activation and at final confirmation.
It creates an immutable approval and a mutable output with exact ownership checks.
It validates effective RBAC and verifies the same producer image before it enables the controller arguments.
It confirms publication renewal, current metrics and structured logs.
Its41 local tests, including the existing helper tests, pass.

[The actual invocation](docs/evidence/live-issuer-publication/publisher-command.json) records all public pins.
It uses the canonical SPIRE manifest digest from [the recovery ledger](docs/evidence/spire-recovery/image-pin.json).
Do not substitute the synthetic Docker archive import digest as a pull reference.
Do not run the old trial cleanup against this persistent activation.
A failed activation uses a resourceVersion-changing rollback fence. It does not adopt foreign resources or remove authority state.

## What the producer does

The administrator supplies an immutable ConfigMap with approved public certificates.
Configuration pins the source UID, output UID, cluster name, root fingerprint and minimum approval generation.
The producer reads the API directly. It validates certificates and the approved cluster-to-trust-domain mapping.
It writes a bounded publication to an existing output ConfigMap.
The output contains public material, provenance, version floors and a short lease.

A hash detects changed content. It is not an authority signature.
Verified Kubernetes TLS, restricted permissions and independent configuration provide the API boundary.
No root private key is placed in either cluster or the evidence.

## Exact build and deployment

| Item | Qualified value |
| --- | --- |
| Source | `f5fe9992da855a22660c07b141e19feee50310ba` |
| Image | `localhost/cmtc:lineage-f5fe9992da` |
| Configuration ID | `sha256:3f5839e26f82395d820cd2fc4439648a7e9fa3957544c705b53092031d7c9be7` |
| Platform | Linux ARM64 |
| Toolchain | Go 1.27.3 |
| Runtime | Pinned distroless Debian 13 |
| Runtime provider | Existing Colima `cmtc-cilium` Docker provider |
| Build provider | Host Podman, explicit `cmtc-ubuntu-build` connection |

[The image ledger](docs/evidence/approved-issuer-lineage/image.json) records the builder, runtime digest, archive hash and binary hashes.
[The build command](docs/evidence/approved-issuer-lineage/build-command.json) records the exact argument list.
The builder configuration ID is local to this host. It is not a portable registry reference.
[The Podman guide](docs/development/PODMAN_LOCAL_VALIDATION.md) describes the prepared environment.

Podman built the image from an exported, committed source tree.
The exported Go files matched the tested source hashes.
The archive was imported into all four existing kind nodes.
CRI checks verified the configuration ID, source label and ARM64 platform.
Running Pod digests matched the imported image manifests.
Each running binary matched the recorded SHA-256.

[The rollout ledger](docs/evidence/approved-issuer-lineage/baseline-rollout.json) covers all six containers.
Only their image field changed. Their service accounts, privileges and arguments stayed intact.

## Local test loop

1. Build the image with host Podman.
2. Export the image as a Docker archive.
3. Import the archive into `cmtc-a`.
4. Import the archive into `cmtc-b`.
5. Verify each node's imported image.
6. Run the issuer-profile helper.
7. Verify central metrics.
8. Run the application regression tests.

The helper is [test-issuer-profile.py](scripts/lab/issuer-profile/test-issuer-profile.py).
It requires the full source, configuration and binary hashes.
It uses the existing controller and service account.
It creates only owned ConfigMaps, a restricted Role and its RoleBinding.
It restores the exact controller template before deleting those resources.
UID and resourceVersion preconditions protect cleanup.

The public fixture generator retains no signing keys.
Its certificates test publication. They are not a production workload authority.

## Completed direct-root trial

These results apply to source `7e606195f5`. The evidence remains available.

- CMTC unit/race tests:52 top-level tests and150 subtests passed. Vet passed.
- Helper checks:22 tests passed after correcting two rollout/scrape timing errors.
- Both clusters passed publication, idle stability, lease renewal and restart-floor checks.
- Both clusters passed source deletion, UID replacement and generation rollback checks.
- Both clusters rejected wrong roots, duplicate issuer keys and expired approvals.
- Both clusters preserved corrupt output and missing-output boundaries.
- Both clusters recovered after explicit administrator repair.
- Real logs contain stage, attempt, elapsed time, deadline and retry fields.
- All four metric families were scraped locally.
- Fresh B-to-A remote-write samples were verified centrally.
- Cleanup restored both controllers and left zero owned resources.
- The deployed baseline passed the existing API/policy and36 application-path checks.

[Cluster A report](docs/evidence/issuer-profile-producer/cmtc-a-report.json) and [Cluster B report](docs/evidence/issuer-profile-producer/cmtc-b-report.json) contain actual results.
[Central query evidence](docs/evidence/issuer-profile-producer/central-b.json) records sample timestamps.
The comparison allows10 ms for target timestamps with nanoseconds and samples with milliseconds.
[Raw evidence](docs/evidence/issuer-profile-producer/raw-evidence.tar.gz) retains commands, outputs, logs and the initial failures.

## Metric meaning

The four `cmtc_issuer_profile_` families measure producer attempts, write responses and timestamps.
They are absent when the producer is disabled.
A write acknowledgment does not prove consumption by Cilium or ztunnel.
A source-read timestamp does not prove valid approval.
A publication lease does not prove protected traffic.
[The metric contract](observability/METRICS.md) defines each family.

## Remaining security gates

The Cilium consumer and ztunnel decoder are under local qualification.
Their production ADS delivery and durable transition are unfinished.
Remote workload provenance, effective authorization, admission recovery and actual peer TLS integration remain open.
WireGuard/IPsec composition remains open.
The ClusterMesh-plus-ztunnel startup guard stays closed.
No mTLS or Protected claim follows from these producer tests.

## Approved cluster-intermediate support

The next producer source increment accepts the intended Option A hierarchy:
organization root → cluster intermediate → explicitly pinned SPIRE CA → workload SVID.
The existing direct-root form remains supported.
The cluster intermediate is public approved lineage. It is not a workload signer.

Approval includes exactly one parent certificate in `chainPEM`.
The verifier checks its exact root signature, key usage, validity and path depth.
It rejects missing, extra, cyclic, substituted and reused cross-cluster parents.
The parent expiry bounds the publication lease.
SPIRE's optional CA URI SAN must equal the independently approved trust domain.
It cannot contain a workload path or additional names.

The complete CMTC race suite passes57 top-level tests and172 subtests.
No test failed or was skipped. Three packages contain no tests.
Formatting and vet pass on the same ARM64 source snapshot.
[The source ledger and raw log](docs/evidence/approved-issuer-lineage/root-summary.json) retain the checks.
The new ARM64 image is deployed in all six containers. Their running binaries match the source ledger.
The API/policy and36 app paths pass after rollout. Both real clusters pass parented-profile publication, renewal, restart, invalid-input and recovery checks.
Fresh B-to-A producer telemetry is verified. Cleanup reports no errors.
[Cluster A report](docs/evidence/approved-issuer-lineage/cmtc-a-report.json), [Cluster B report](docs/evidence/approved-issuer-lineage/cmtc-b-report.json) and [raw evidence](docs/evidence/approved-issuer-lineage/raw-live-evidence.tar.gz) retain the actual output.
[Application output](docs/evidence/approved-issuer-lineage/baseline-test.log) retains the actual responses.
Live SPIRE certificates, matching Cilium/ztunnel consumers and actual traffic protection still need qualification.
