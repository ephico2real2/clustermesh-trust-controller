# Required Cursor deliverable: complete code files

The human explicitly requires full code snippets in a saved file that the primary engineer copies into the implementation.

Use the already selected `grok-4.7-xhigh` model and read-only planning mode. Return a Markdown implementation document suitable for `docs/research/cursor/CLUSTER_TRUST_IMPLEMENTATION.md`.

For the chosen first independently testable cluster-bound trust increment:

1. Give every exact target repository path and whether each file is new or changed.
2. Supply complete contents of all new Go/Rust/test files. For existing large files, provide complete replacement functions plus exact import/type/configuration changes, or an apply-ready unified patch. No ellipses, TODO stubs, omitted helper functions, invented existing APIs or pseudocode presented as finished implementation.
3. Include actual positive, wrong-issuer/domain, malformed/ambiguous identity, stale/revoked bundle and recovery tests appropriate to the slice. Distinguish deferred integration gates from implemented tests.
4. Include exact local test/build commands, declared dependencies and source assumptions. Do not claim the code has compiled or passed tests unless the primary independently verifies it.
5. Keep the ClusterMesh compatibility guard and actual platform protections intact. Do not add a permissive common-root union or production mock bypass to make tests green.
6. Explain the boundaries of this increment and the smallest follow-up needed to wire it into the actual certificate/verifier path. Label any still-unimplemented APIs honestly.

The primary saves your response to the implementation document, reviews it against current source, copies accepted files/patches into the fork, fixes issues and qualifies actual local images/runtime. Cursor must not directly edit source or mutate the lab.

## Expanded human requirement: cover the complete unfinished mandate

The human explicitly requires you to cover ALL of the following, not only the cluster-trust verifier:

- Authenticated native remote workload discovery (origin authority, recurring sync epochs, malformed records, ordered deletes, UID/address reuse, partition/expiry/reconnect and recovery).
- Cluster-bound identity and domain-to-issuer verification (same namespace/SA names across clusters, wrong-domain signer, unauthorized issuer, bundle rotation/removal and retained flows).
- Effective authorization compiled from real Cilium policy, preserving explicit deny and finer pod-label restrictions, original application ports, named ports, unsupported policy rejection, missing/NACKed/stale policy, and plaintext-negative tests independent of a port allowlist.
- Durable admission and recovery (synchronous intent-only persistence before CNI success; Namespace/Pod/sandbox incarnation; first-packet hold; corruption/fsync failure; API outage, restart, late ACKs and exact retirement). A standalone file store or a readiness log alone cannot satisfy this.
- Workload mTLS separately composed with WireGuard and IPsec. Qualify A→B and B→A with Global Services and direct Pod IP at TCP/80,8080,31337. Missing either required layer must block, and packet captures, actual peer identities and policy verdicts must agree on the same flows.
- A NEW custom CMTC Go+eBPF observe-first prototype, separately gated from the unprivileged Observe DaemonSet, followed by deny admission only after CNI/restore safety and then a Cilium-native port. Existing Cilium BPF compilation is not a CMTC program. Preserve Cilium TCX links/tail anchor, reject legacy-TC/netkit/no-TCX, fence interface reuse and keep counters explicitly pre-verdict.
- Observability: retain two consolidated dashboards and all nine originals, implement actual metric contracts as stories land, keep unavailable/planned metrics honest, validate live queries, real-load outputs and screenshots in both themes. Attempts, rejections, mTLS TCP connections, HTTP requests and TLS handshakes are distinct quantities.

Current retained cmtc-a/b show ClusterMesh/reachability only. Proxy image import/version Jobs are not a running workload-mTLS deployment. Do not mark these gaps complete in your response.

Deliver a dependency-ordered design/test ledger spanning the entire list. For every stage, provide exact files/interfaces, positive/negative/failure/recovery cases, concrete test inputs/assertions/commands, evidence outputs and criteria before removing compatibility guards. For each code increment you propose, include complete executable test snippets with the full implementation files/patch; no placeholder helpers or invented APIs. If a test relies on infrastructure not implemented yet, label it a required future integration gate, not a passing unit test.

You may inspect these additional PRIMARY-UNACCEPTED proposals, but critically review them rather than assuming correctness:
- docs/research/cursor/inputs/UNREVIEWED_EBPF_PROPOSAL.md (untested Go/C eBPF observe-only loader and opt-in DS proposal)
- docs/research/cursor/inputs/cmtc-required-intent-proposal.go.txt and the adjacent *tests-proposal.go.txt files (untested persistence/test proposals).
Current primary code now includes pkg/ztunnel/admission/intent_store_linux.go as an UNQUALIFIED new helper with held directory descriptors and injected write/sync/rename operations; it is not wired into CNI/restore yet. Do not overwrite it. Coordinate with that actual interface if proposing integration tests.
