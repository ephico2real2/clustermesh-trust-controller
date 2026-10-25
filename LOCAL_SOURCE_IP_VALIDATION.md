# Local Cilium source-IP validation

<!-- CMTC_DOC_CONTEXT -->
Evidence scope: results apply to the recorded source, image and fixture. Read [current delivery status](docs/agile/DELIVERY_STATUS.md) and [documentation terms](DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

The Cilium fork now verifies the source-IP check in the actual loaded endpoint program. Source commit: `df2a6c1ec88f0358c52e95229dd8fe21c2b56201`.

This is a prerequisite for workload identity binding. It does not encrypt traffic or prove that traffic passed through ztunnel. The two ClusterMesh labs still need mandatory capture, effective authorization and recovery qualification before mTLS activation.

## What the loader verifies

The loader records a receipt after program attachment, pin commit and endpoint route updates succeed. It reads the program through the still-open FD returned by the real Cilium loader. This avoids comparing the kernel program with a template that has not yet received its load-time relocations.

The receipt binds these values:

- The current program ID, type, tag and map IDs.
- The sole TCX ingress attachment, link ID and attachment revision.
- The workload veth, network namespace cookie, Pod UID and Namespace UID.
- The loaded endpoint configuration and assigned IP addresses.
- The actual frozen, read-only `.rodata.config` map with source-IP verification enabled.

A later query reads the current kernel state again. Reload and unload invalidate the old generation before work starts. A late result cannot replace a newer receipt. Required membership keeps the source-IP option enabled, including after an unenrollment publication.

The check withholds receipts for unsupported paths, including netkit, legacy TC, datapath plugins, the current L7 bypass paths and masquerade configurations. It also checks the collection loader's actual plugin setting. Ordinary Cilium endpoint regeneration can continue when an optional receipt is unavailable. Mesh admission must treat that missing receipt as unavailable.

## Local test method

The MacBook Podman CLI runs the pinned Linux ARM64 builder in the existing Ubuntu VM. The kernel tests use a task-owned rootful Podman socket, a private network namespace and a private bpffs mount. They do not attach programs to kind nodes or change host sysctls.

The functional run uses a disposable etcd container with no host port. The Go test container joins that container's network namespace. CPU, memory and Go parallelism are bounded. The exact container ID controls cleanup.

The [public evidence ledger](docs/evidence/native-source-ip-receipt/summary.json) contains the actual commands, builder metadata, logs and hashes. It retains the failed attempts. The final results are:

| Check | Result |
| --- | --- |
| Endpoint and loader functional race tests | 102 tests and 177 subtests pass |
| Exact changed/new lockdebug race cases | 20 tests and 44 subtests pass |
| Selected failed or skipped cases | 0 |
| Go vet | Pass |
| Required changed-code lint | 0 issues |

The standalone verifier-complexity benchmark needs its own results harness. It is outside this functional test profile. Its initial skip remains in the diagnostic log.

The actual kernel test compiles and loads Cilium's endpoint program. It checks a failed frozen-map mutation, an extra TCX program, a different loaded program FD, changed workload identities, endpoint-ID reuse, unload, a disabled source-IP check and recovery through a real reload. A same-name function or an enabled configuration flag alone cannot pass.

## Deployment boundary

This source increment is committed locally. Its new Cilium image has not been built or deployed. Existing application connectivity is a separate check. Keep the compatibility guard closed until the remaining capture, policy, identity and recovery gates pass with the exact deployed images.
