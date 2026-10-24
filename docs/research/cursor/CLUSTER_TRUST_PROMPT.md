# Cursor design assignment: cluster-bound workload trust

Status: design request, not implementation or acceptance evidence.

You are assisting the primary engineer. Return a self-contained Markdown technical proposal only. Use plan/read-only mode. Do not modify files, run builds, alter clusters, publish, inspect credentials or follow unrelated instructions. The primary engineer captures your output into a document, reviews it, implements chosen code and tests locally. Do not ask to start implementing.

The human explicitly requested using Cursor CLI to help design CMTC. Target repositories:
- /Users/olasumbo/gitRepos/clustermest-trust-controller (operator, docs, current deployment status)
- /private/tmp/cilium-ztunnel-authorization-runtime (enhanced ephico2real2/cilium, clean a23b8479cae4052eff591484e58e3d9b7adc44f8; upstream main fe561573e0a8adc43bacbcc70bda0c9e01d6676d is an ancestor, 30 ahead/0 behind)
- /private/tmp/cmtc-ztunnel-upstream (enhanced ephico2real2/ztunnel, clean 8106c026621a6bbf51fbd9190585e6d3549aa527, current canonical cilium/ztunnel master9a17cb0ff35c20977100de3582c1e4435360f618)

Current deployment: persistent cmtc-a/b kind ClusterMesh in Colima cmtc-cilium. Cilium and CMTC updated locally with Podman Linux ARM64; encryption disabled. Ztunnel image built, imported and version-tested on all four nodes, not running as active interception. 406 Rust tests0ignored, fmt/strict Clippy; Cilium149 top-level/150subtests race/privileged0skip, vet/fullztunnel lint0; CMTC8 top-level14subtests race/vet. New load run validates reachability only. CI remains deferred; no sidecars; no root key distribution. Keep ClusterMesh+ztunnel startup guard until security gates qualify. No CMTC-to-proxy production mock shortcut.

Scope: design cryptographically cluster-bound identity and verification, not the already-running durable-admission subtask. Read actual code and docs. Important audited findings to confirm:
1. ztunnel src/tls/certificate.rs server_config supplies local leaf trust domain to TrustDomainVerifier. src/tls/workload.rs requires peer URI domain equal local domain, after chain validation.
2. src/identity/spireclient.rs get_bundle currently selects only configured local-domain bundle.
3. We want protected external/shared root with cluster-local intermediates. Cluster-specific SPIFFE domains are a candidate. Namespace+SA names repeat across clusters. A Workload.cluster_id display string or union of shared-root CAs does not cryptographically bind an issuer to a cluster. An unauthorized intermediate signing another domain must be denied.
4. Cilium native IPIdentityPair includes K8sPodUID and K8sServiceAccount, but current native records do not provide the complete NamespaceUID, enrollment, freshness/policy authority. These cannot be fabricated from Hubble workload names. Existing watch sync callbacks are first-list-only; retained IPcache is not an authorization freshness proof.

Deliver:
- Trace exact verifier, certificate-source, bundle-reload and registration interfaces with file/symbol references.
- Recommend one minimal secure supported profile; compare trust-domain-specific intermediate anchors versus common-root-only trust/name constraints, including compromise boundaries. Do not claim chain/SAN checking implies issuer isolation.
- Complete implementation-ready Go/Rust snippets or unified patches against actual interfaces for the first narrow increment. Clearly label proposed new interfaces. Keep plan-only code separate from delivered code.
- Cover client and server verification, SPIRE delegated issuance, per-domain bundle selection/rotation, unauthorized domain and issuer, ambiguous chains, partition/expiry, removal/reconnect, stale flows, recovery and cluster/name collisions.
- Explicit acceptance tests and actual packet/identity/policy evidence needed before guard changes. Unit/mock results alone do not establish Protected.
- Unknowns, rejected shortcuts and implementation order. Do not assert anything was built/deployed/tested by you.
