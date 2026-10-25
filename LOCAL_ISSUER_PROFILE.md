# Local issuer-profile qualification

The public issuer-profile producer passes local tests on both mesh clusters.
It does not establish workload mTLS.

The tested image is now the baseline for both controllers and all four node agents.
Baseline mode remains Observe. The producer is an explicit opt-in feature.
The test enabled the producer, then restored its configuration and removed its test resources.
No issuer profile is active after cleanup.

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
| Source | `7e606195f58359b0e0af82f219cafd5291268c67` |
| Image | `localhost/cmtc:issuer-7e606195f5` |
| Configuration ID | `sha256:6d4b28d1935e3fecf260ee90e2baec844adcce63ee650d0cdcf61e50ac4439f6` |
| Platform | Linux ARM64 |
| Toolchain | Go 1.27.3 |
| Runtime | Pinned distroless Debian 13 |
| Runtime provider | Existing Colima `cmtc-cilium` Docker provider |
| Build provider | Host Podman, explicit `cmtc-ubuntu-build` connection |

[The image ledger](docs/evidence/issuer-profile-producer/image.json) records the builder, runtime digest, archive hash and binary hashes.
[The build command](docs/evidence/issuer-profile-producer/build-command.json) records the exact argument list.
The builder configuration ID is local to this host. It is not a portable registry reference.
[The Podman guide](docs/development/PODMAN_LOCAL_VALIDATION.md) describes the prepared environment.

Podman built the image from an exported, committed source tree.
The exported Go files matched the tested source hashes.
The archive was imported into all four existing kind nodes.
CRI checks verified the configuration ID, source label and ARM64 platform.
Running Pod digests matched the imported image manifests.
Each running binary matched the recorded SHA-256.

[The rollout ledger](docs/evidence/issuer-profile-producer/baseline-rollout.json) covers all six containers.
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

## Results

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
This source result does not update the deployed image table above.
Live SPIRE certificates, matching Cilium/ztunnel consumers and actual traffic protection still need qualification.
