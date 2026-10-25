# Initial threat model

<!-- CMTC_DOC_CONTEXT -->
Design scope: proposed behavior requires the stated acceptance tests. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Status: Proposed; architecture/security review and runtime evidence pending. Date: 2026-10-23. Inputs: [source audit](../research/SOURCE_AUDIT.md), [failure test matrix](SECURITY_AND_FAILURE_TEST_MATRIX.md).

## Assets and trust boundaries

Protect root/intermediate signing authority, workload private keys, cluster-bound SPIFFE identities, enrollment/exclusion decisions, Cilium authorization, bundle generations and protection observations. Boundaries are organizational root→cluster issuer, SPIRE server→node/workload, ClusterMesh peer→local discovery, Cilium→ztunnel, controller→node observer, Kubernetes RBAC→namespace metadata and exporter→monitoring. A compromised node can expose its own workloads; that must not become authority for another cluster. A compromised cluster intermediate is a separate, higher-impact case requiring verifier constraints or trust withdrawal.

CMTC owns desired policy and trust coordination. Cilium owns packet enforcement. SPIRE owns attestation and SVID issuance. trust-manager copies public certificates; it does not attest to consumer reload. Admission can constrain changes but cannot enforce packets from existing pods.

| Threat | Proposed mitigation / unresolved decision | Required negative evidence |
|---|---|---|
| Spoof a foreign cluster with the same namespace/service account under the common root | Explicitly bind expected cluster, workload identity and allowed issuer/trust-domain at issuance and verification. Distinct intermediate keys alone are insufficient. V05/V08 show missing cluster binding in current mappings. | A foreign intermediate signing an otherwise plausible identity is rejected; same names across clusters cannot collide. |
| Forge remote workload or keep stale ipcache/xDS metadata | Authenticate registry/discovery source; cluster-qualified keys; deletion/UID lifecycle; bounded freshness; deny unknown peers. | Forged/replayed exports, stale pod IP reuse and delete/recreate cannot authorize a connection. |
| First-packet plaintext, relabel race or ztunnel/SPIRE failure | Cilium gate before traffic can leave; atomic generation transitions; no permissive fallback. No existing gate is established by this review. | Continuous packet capture during new pods, relabels, failed ZDS ACKs and crashes shows no unauthorized protected traffic. |
| Bypass application-port policy inside HBONE | Preserve original tuple and authenticated identity at the enforcement point; empty xDS authorization resources are not sufficient. | Allowed HBONE listener with denied application port still denies the application flow. |
| Exfiltrate signing keys | Keep organizational root outside clusters, preferably HSM/external issuer; SPIRE intermediate keys stay within their intended signing boundary. CMTC gets public bundles, not signing secrets. Audit existing built-in CA mounts before reuse. | RBAC/mount inspection finds no root/intermediate key distributed by CMTC to nodes/namespaces; unauthorized CSR and secret access fail. |
| Exclusion or reserved-label privilege escalation | Restrict policy/exemption/label writes, log decisions, preserve platform→exclusion→inclusion precedence, manage only owned fields. | Unauthorized exclusion/relabel requests fail; excluded sources do not gain protected-destination access. |
| Replay a healthy observation or retire trust during partition | Authenticated ACKs bound to cluster/node/UID/generation/digest and freshness; all required consumers must confirm new trust; separate emergency revocation. | Stale ACK, disconnected cluster or forged generation blocks routine retirement and never produces fresh `Protected`. |
| Disable required WireGuard/IPsec while HBONE still works | Independent transport capability/state evidence and enforcement; reject unsupported compositions. | Lost WG key or XFRM state cannot produce required-layer plaintext. TLS success does not satisfy the transport check. |
| Break platform dependencies through broad default enrollment | Protect system/control-plane/hostNetwork inventory and design narrow non-enrolled endpoint paths. Do not use blanket security bypass. | API/DNS/webhook/upgrade/recovery probes pass while unauthorized platform-adjacent application flows remain denied. |
| Hide an outage behind missing metrics or excessive cardinality | Unknown for missing/stale samples, bounded aggregate labels, authenticated scrape configuration and logs for detailed identity. | Exporter disappearance and missing cluster series alert; arbitrary namespace labels/identity strings cannot grow aggregate series without bound. |

## Current implementation findings

The [PKI flow](../../PKI_TRUST_FLOW.md) documents the approved cluster intermediate and exact SPIRE signer. A common root does not authorize an alternate peer signer.

The experimental registrar has server Admin access inside the SPIRE server Pod. That is a distinct authority from the node agent Admin API. A read-only socket mount still permits RPCs. Keep filesystem permission, UNIX peer verification and API caller authorization as separate checks. [The registration review](../../SPIRE_REGISTRATION_DESIGN.md) records the residual single-writer and administrator trust assumptions.

Proxy source tests reproduced buffered-plaintext and delayed-CONNECT bypasses under stale authority. The corrected source checks both I/O layers and rechecks admission after awaited work. [The local evidence](../evidence/native-issuer-profile/live-provider/summary.json) does not qualify an undeployed proxy.

A delegate permission error identifies a caller problem. A target credential test requires an authorized control. A timeout cannot establish policy denial. Registration deletion does not revoke issued certificates or close active flows.

## Recovery and approval gates

Routine rotation: distribute old+new public roots → verify actual SPIRE/ztunnel consumption → switch issuance → verify SVID/probe convergence → drain old connections/SVIDs → retire. A partition blocks unsafe progress. Emergency intermediate/root compromise requires an explicit isolation/revocation plan even when availability is reduced; do not treat normal rollback as revocation.

Resolve identity/issuer binding, first-packet gate, decrypted L4 authorization, external CA delivery and platform interoperability before accepting the relevant ADRs. Validate the Cilium ztunnel dependency against the no-Istio boundary. No guarantee of universal TCP mTLS, UDP protection or OpenShift support follows from this model. Security review must name residual risks and a recovery owner before enabling live enrollment.
