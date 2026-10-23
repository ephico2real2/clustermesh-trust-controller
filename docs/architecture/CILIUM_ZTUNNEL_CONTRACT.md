# Proposed Cilium remote workload and authorization contract

Status: proposed engineering contract, 2026-10-23. Based on the [pinned mesh comparison](../research/MESH_MTLS_COMPARISON.md) and [Cilium audit](../research/SOURCE_AUDIT.md). This is the next implementation boundary; no new production API or enforcement capability is implied.

Implementation tracking: [Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1) starts the protocol portion with the exact `cilium/ztunnel` v1.0.0 Authorization schema, a separate Go security package, independent wire fixture and reproducible generation tests. [Focused CI passed](https://github.com/ephico2real2/cilium/actions/runs/40022647528) at `636e441044379d48db0686eb21becf9351f782f6`. This is partial groundwork for slices 1 and 3 below; neither remote discovery nor authorization delivery/admission is implemented by that patch. Keep every runtime acceptance gate open.

## Ownership

CMTC evaluates namespace intent, coordinates trust lifecycle and reports verified observations. Cilium owns local interception, endpoint identity, service translation, network policy and xDS. SPIRE owns workload attestation and SVID issuance. Ztunnel authenticates peers and enforces the supported destination L4 policy. WireGuard/IPsec protects node transport independently. An admission result must combine these actual capabilities without letting one stand in for another.

Local ZDS continues to exchange local workload/netns resources. Remote workloads enter the xDS discovery graph through a new ClusterMesh adapter; they never cause a node to enroll a remote network namespace.

## Discovery record

The authenticated export must bind the following fields together:

| Field | Required meaning |
|---|---|
| Origin | Configured cluster authority and cluster ID; reject payloads claiming another origin. |
| Object identity | Namespace UID, Pod UID and service-account identity; namespace/name alone cannot survive delete/recreate safely. |
| Resource key | Cluster-qualified kind/namespace/name plus UID incarnation in the adapter. Any wire key mapping must preserve deletion/recreation ordering. |
| Addresses | Validated pod addresses and network ID; address ownership must agree with the configured cluster/ipcache provenance. |
| Expected principal | Exact SPIFFE identity and approved trust/issuer mapping; never infer it only from an IP or telemetry Workload record. |
| Enrollment | Explicit namespace intent plus supported workload type; hostNetwork/platform paths remain outside initial enrollment. |
| Version | Origin epoch/revision, policy generation/digest and expiry/freshness bounds; reconnect snapshots cannot revive removed records. |

Import must validate the transport peer against the configured origin, then validate record ownership. This is a proposed new interface; CEP/CES, remote identities and the existing Hubble workload export do not currently provide this complete contract. No adapter may fabricate a service account from an endpoint's display name. Conflicting origins, missing identity fields and unknown incarnations block protected routing.

Removal withdraws address lookup and authority for that incarnation. Full resync must reconcile deletions, not only upserts. A revoked origin loses its records and policy-derived permissions. Specify a bounded stale-state policy for temporary partitions before enabling enforcement; neither indefinite acceptance nor automatic plaintext fallback is permitted.

## Identity decision

Keep the protected shared root and cluster-local intermediate keys. Select an identity scheme only after a two-cluster issuance/verification spike. The leading candidate is cluster-specific trust domains using the existing namespace/service-account path, with explicit permitted peer domains and issuer constraints. The current Cilium proxy's same-domain verifier needs changes for that candidate. A shared trust domain instead requires a different cryptographically verifiable cluster binding; the display-only `cluster_id` is insufficient.

The issuer/attestation path must refuse cluster A requests for cluster B identities. Peer verification must refuse a certificate that has the expected URI but an unauthorized issuer binding. If the chosen common-root PKI cannot enforce that property, record the larger compromise boundary and do not claim issuer isolation. Public trust-bundle propagation, issuer selection and actual consumer reload evidence are separate operations.

## Destination authorization

Use the **pinned Cilium proxy's** `istio.security.Authorization` descriptor and type URL. Add generated types and a real delta resource lifecycle to Cilium's xDS server, including versions, subscriptions, ACK/NACK and removals. Keep Address and Authorization resource tracking distinct; a local ZDS ACK cannot acknowledge authorization.

Start with a narrow, explicitly supported TCP L4 subset. Compile from the effective Cilium policy authority, preserving selector logic, explicit denials, application port and peer identity; resolve named ports against the destination incarnation. A separate CMTC allow policy must never override a Cilium deny. Reject unsupported egress, L7, FQDN, CIDR or other policy combinations until their semantics are traced and tested. Unsupported cases remain in Observe and cannot enter a Protected profile.

Use exact SPIFFE principals for cluster-specific permissions; this proxy's namespace/service-account matcher ignores the trust domain. A service-account identity also cannot distinguish two pods with different policy labels that share that account. Preserve those finer Cilium restrictions through the authenticated datapath or reject the profile. Do not convert a label-specific allow into a broader service-account allow.

The receiving proxy must check the authenticated source principal and resolved application destination, validate that the CONNECT target belongs to the local destination workload, and enforce the effective policy before opening the application connection. Tunnel port 15008 is transport plumbing. Allowing it broadly does not preserve an existing port 80 denial or caller restriction. Cilium's outer eBPF checks and inner proxy checks need a documented division of responsibility, including egress, return traffic, socket-LB and reverse NAT.

## Traffic admission and observation

Protected admission needs all of the following for the **same workload UID/incarnation and configuration generation**:

1. Platform classification permits enrollment and local interception is installed with a first-packet hold.
2. The workload SVID and required trust bundle are valid and consumed by the actual proxy.
3. Expected local/remote identity records are authenticated, current and unambiguous.
4. Every required policy is present and active, including explicit plaintext denial; missing references fail closed.
5. Required WireGuard/IPsec state and the qualified datapath composition are ready.

Independent xDS type ACKs cannot create a transactional admission barrier by themselves. The proxy or datapath must hold new protected traffic until the complete generation is active. Restart, reconnect, NACK, missing-reference, removal and stale-policy paths must preserve that hold. Initial implementation must not rely on a transient bootstrap DENY that can disappear during resync.

Observations exposed to CMTC should include node/proxy identity, workload and namespace UID, software/protocol versions, intent generation, trust/policy digests, local interception state, active admission state, observation time and reason. Bind them to an authenticated observer. CMTC can then report Unknown/Blocked for absent or stale evidence. Successful ACKs and namespace labels remain insufficient for Protected; runtime positive and negative canaries validate the claimed path.

## Reviewable fork slices

| Slice | Code boundary | Acceptance before the next security claim |
|---|---|---|
| 1. Protocol and discovery | Cilium Go/Hive remote exporter/importer, cluster-qualified keys, exact proxy protobuf pin | Colliding names/IPs, UID recreation, deletes, reconnect and unauthorized-origin records are tested. No guard removal yet. |
| 2. Identity spike | SPIRE registration/attestation and proxy verifier | Same-name namespace/SA in two clusters is distinguishable; wrong issuer/domain/cluster is denied. Prove image provenance. |
| 3. L4 policy and admission | Cilium effective-policy translation, real authorization delta stream, proxy/datapath hold | Allowed peer:80 passes; stranger:80, allowed peer:81, plaintext, missing policy, L7 profile and reorder/restart races deny. |
| 4. Supported ClusterMesh profile | Capability validation and narrowly revised compatibility guard | Direct pod-IP and Global Service paths pass both directions plus disconnect/recovery tests. |
| 5. Layered profiles | Independent workload/transport settings and WG/XFRM datapath | Separate WireGuard and IPsec runs prove inner workload identities and outer encryption; loss of either required layer blocks traffic. |

Use an isolated Cilium fork branch based on the selected pin. Preserve the user's existing Hubble branch. Any required Rust proxy change is tracked explicitly rather than described as Go-only work. Upstream messages remain a separate authorized activity.

## CI acceptance matrix

Reuse `examples/apps/shop` with distinct service accounts for POS/stranger in the encrypted fixture; the current baseline app manifests do not yet establish distinct mTLS principals. Reuse `examples/apps/clustermesh` for cross-cluster-only backends. Run each case on same-node, different-node and cross-cluster paths where applicable:

| Test | Expected evidence |
|---|---|
| Authorized source, intended application port | Success plus verified peer identities and policy generation. |
| Different SA; same SA/namespace in unapproved cluster; wrong issuer | Denial attributable to authenticated identity policy, not only a network timeout. |
| Correct peer, forbidden application port | Denial despite a working HBONE tunnel. |
| Same service account, forbidden pod labels | Denial remains effective even though the pods share an mTLS principal. |
| Direct plaintext / non-enrolled caller | Denial at a protected destination with no fallback. |
| Missing policy, removed policy, NACK, reconnect with initial resource versions | No admission window; intended revocation takes effect. |
| Pod/namespace recreation, endpoint IP reuse | Old identity/policy observation cannot authorize the new incarnation. |
| Cluster disconnection, stale export, SPIRE/proxy/Cilium outage | Bounded behavior, no downgrade; recovery does not bypass admission. |
| Required WireGuard or IPsec loses keys/state | Traffic blocks; restore resumes only with both layers verified. |
| API, DNS TCP/UDP, webhooks and excluded/platform workloads | Baseline platform health remains intact. |

Preserve packet captures, authenticated connection/policy decisions and transport counters/state alongside machine-readable assertions. Captures alone cannot prove the caller was authorized; screenshots cannot replace security assertions. The current Observe workflow reports encrypted profiles as blocked and must continue doing so until these cases run against the implemented fork.
