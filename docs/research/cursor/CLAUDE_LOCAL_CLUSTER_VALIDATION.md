# Claude local cluster validation

The user authorized this change on 2026-10-25:

> opus can test the code locally and bind to the cluster api using the kind context to test immdaitely. tell to do this where appropriate

This instruction replaces the earlier assignment's prohibition on local cluster API access. Claude Code Opus 5.5 High can use the existing lab for relevant tests. Continue the full native ClusterMesh workload-mTLS mandate.

## Lab ownership

Use only `kind-cmtc-a` and `kind-cmtc-b`. Use the existing kubeconfig at `/private/tmp/cmtc-a-b-20261024.kubeconfig`. Do not print its contents. Specify the context in each command. Preserve the Colima `cmtc-cilium` runtime and KVStoreMesh.

Verify these `kube-system` namespace UIDs before changes:

| Context | UID |
| --- | --- |
| kind-cmtc-a | bb7182c7-de95-4e70-816a-a1400d755794 |
| kind-cmtc-b | f2687af6-bd96-45a3-98a2-d1397a3ee244 |

Coordinate through `review/LAB_OWNER.json`. One agent owns live writes at a time. The primary can inspect the same lab without changing its resources. Do not create replacement clusters or change the runtime provider.

## Allowed work

Inspect the API, node and Pod inventory, logs, events, public configuration, metrics and actual image identities. Create and run scoped test workloads and Jobs. Use Podman on the MacBook to build the changed Linux ARM64 images. Import them by archive into the existing kind runtime. Deploy a qualified candidate when its required security gates pass. Record the source diff, toolchain, image configuration ID, loaded image identity and running binary revision.

Test the real native path. Use local, A-to-B and B-to-A traffic through Global Services and direct Pod IPs. Include ports 80, 8080 and 31337. Test unenrolled and invalid identities, effective policy denial, stale or NACKed state, disconnect, restart and recovery. Preserve the existing applications and signer state. Use bounded probes and test-owned resources. Save public evidence, actual exit status and counts.

Read and snapshot the affected resources before changes. Bind cleanup and restoration to their exact UIDs and resource versions. Do not run broad deletion, pruning or unrelated rollouts.

## Boundaries that still apply

The user has not explicitly approved the previously rejected SPIRE Admin DAC migration. Do not change that socket's ownership, modes, group or mount access. Do not copy or print the protected root private key, tokens, kubeconfigs or private credentials into evidence.

Keep the Cilium compatibility guard closed until the required identity, capture, authorization and recovery gates pass. A source test, ACK, label, certificate or HTTP success alone does not establish Protected. The deny-only quarantine draft cannot enable authenticated traffic. Keep sticky Required intent separate from quarantine.

Do not add application sidecars or a production mock bridge. Keep node ztunnel for workload TLS. Keep WireGuard/IPsec as a separate transport layer. Do not substitute a stock image for the enhanced fork. A transport-only packet trace does not prove workload mTLS.

The primary still owns Git pushes, registry publication and CI. This instruction authorizes local tests and applicable local deployment. It does not authorize external publication or changes to unrelated workloads.

## Current source handoff

Use the four isolated checkouts under `/private/tmp/cmtc-opus-final-20261025`. Read current `review/OWNERSHIP.json`, `BUILD_SLOT.json`, `CLAUDE_NEXT_CILIUM.md`, `PRIMARY_REVIEW_NEXT.md`, `CILIUM_LIFECYCLE_PROPOSAL.md` and the quarantine-separation patch notes. Preserve every existing dirty increment. Apply reviewed patches against the actual interfaces and test them locally.

The ztunnel handshake collector passed its first full profile. Pool recovery and active-session work need the final full rerun. The SPIRE/registrar candidate still needs tests. Give the primary the compiler slot for that qualification, then coordinate the exact images and live tests.
