# Cilium remote workload and authorization contract

<!-- CMTC_DOC_CONTEXT -->
Design scope: proposed behavior requires the stated acceptance tests. Read [current delivery status](../agile/DELIVERY_STATUS.md) and [documentation terms](../../DOCUMENTATION_GUIDE.md).
<!-- /CMTC_DOC_CONTEXT -->

Status: engineering contract, first written 2026-10-23 and revised 2026-10-25. Most of the contract is now
implemented in our Cilium and ztunnel forks and deployed in `cmtc-a` and `cmtc-b`. The recovery, policy-shape,
transport-encryption and per-connection evidence gates stay open. No `Protected` claim follows from this page.

## Result first

| Contract part | State on 2026-10-25 |
| --- | --- |
| Authenticated remote workload discovery (slice 1) | Implemented, deployed. Every agent reports `1/1 remote clusters ready`. |
| Cluster-bound identity (slice 2) | Implemented, deployed. Each cluster has its own trust domain (`cmtc-a.mesh.example`, `cmtc-b.mesh.example`). |
| Effective L4 policy and admission (slice 3) | Implemented, deployed, traffic-qualified for the allow paths. Deny-policy shapes are unit-tested only. |
| Supported ClusterMesh profile (slice 4) | The blanket startup rejection is replaced by a capability check. Pod-IP and Global Service by ClusterIP pass in both directions. Global Service by name fails (DNS). Recovery is not yet run. |
| Layered transport (slice 5) | Not started. WireGuard and IPsec are not configured. |

Use [delivery status](../agile/DELIVERY_STATUS.md) for the source and image pins. The live traffic record is
[G1 destination sources](../evidence/g1-destination-sources/README.md).

## Ownership

These owners do not change:

- **CMTC** evaluates namespace intent, coordinates the trust lifecycle and publishes approved public issuer profiles.
- **Cilium** owns local capture, endpoint identity, service translation, native network policy, the workload
  quarantine gate, remote workload discovery and xDS.
- **SPIRE** owns workload attestation and SVID issuance.
- **ztunnel** authenticates peers and enforces the destination L4 policy that Cilium delivers.
- **WireGuard or IPsec** protects node transport independently. Neither is configured in the lab.

An admission result combines these capabilities. One capability never stands in for another.

Local ZDS exchanges local workload and network-namespace resources. Remote workloads enter the xDS graph through a
ClusterMesh adapter. A node never enrolls a remote network namespace.

## Discovery record

The authenticated export binds these fields together:

| Field | Required meaning |
| --- | --- |
| Origin | Configured cluster authority and cluster ID. A payload that claims another origin is refused. |
| Object identity | Namespace UID, Pod UID and service-account identity. A namespace/name alone does not survive delete and recreate. |
| Resource key | Cluster-qualified kind/namespace/name plus the UID incarnation. A wire key keeps deletion and recreation order. |
| Addresses | Validated Pod addresses and network ID. Address ownership agrees with the configured cluster and the ipcache. |
| Expected principal | Exact SPIFFE identity and the approved trust domain and issuer. Never inferred from an IP or a telemetry record. |
| Enrollment | Explicit namespace intent and a supported workload type. hostNetwork and platform paths stay outside enrollment. |
| Version | Origin epoch, revision, policy generation, digest and expiry. A reconnect snapshot cannot revive a removed record. |

Import validates the transport peer against the configured origin, then validates record ownership. No adapter
creates a service account from an endpoint's display name. Conflicting origins, missing identity fields and unknown
incarnations block routing to the workload.

Removal withdraws the address lookup and the authority of that incarnation. A full resync reconciles deletions, not
only upserts. A revoked origin loses its records and the permissions derived from them. A partition has a bounded
stale-state policy: neither indefinite acceptance nor plaintext fallback is permitted.

**Implemented (Cilium fork).** The per-peer snapshot store and remote projection gate remote workloads
(`pkg/ztunnel/remote_workload/`). Source membership leases carry each captured workload's state, and since ADR-010
its realized egress policy (`pkg/ztunnel/membership/source_publisher.go`). The record decoder refuses case variants,
duplicate members and unknown members.

## Identity decision

The lab uses **cluster-specific trust domains**: the ztunnel DaemonSet in `cmtc-a` sets
`TRUST_DOMAIN=cmtc-a.mesh.example`, and `cmtc-b` sets `cmtc-b.mesh.example` (read 2026-10-25 from the DaemonSet
environment). The protected shared root and cluster-local intermediates stay as before ([PKI trust
flow](../../PKI_TRUST_FLOW.md)).

The ztunnel fork verifies a peer against the exact approved signer for the trust domain in the peer's authenticated
SAN. It never falls back to the organization root or the local SPIRE root store (`src/tls/workload.rs:389-400` at
`f221f29b59`). The issuer profile that CMTC publishes supplies the approved signers.

Open:

- The issuer and attestation path must refuse a cluster A request for a cluster B identity. That negative test has not
  run against the deployed images.
- A certificate with the expected URI but an unauthorized issuer must be refused. Source tests cover this; a live
  negative test has not run.
- Trust-bundle propagation, issuer selection and consumer reload are separate operations, each with its own evidence.

## Destination authorization

Cilium compiles the destination's ztunnel ALLOW rules from its own effective policy
(`policy.CompileZtunnelTCP`, `pkg/policy/ztunnel_l4.go:286`). A port is admitted only when the destination's realized
ingress permits the source identity **and** the source's realized egress permits the destination. A separate CMTC
allow policy never overrides a Cilium deny.

The egress half cannot be enforced at the source: in-pod redirection hides the original port, and the traffic that
leaves the Pod is HBONE to 15008. [ADR-010](adr/ADR-010.md) therefore delivers each source's realized egress to the
destination:

- The source agent publishes the egress-only snapshot in its membership lease.
- The destination policy owner admits an external caller only with a current lease, the trust domain the issuer
  profile approves, a capture by its source, a policy that decodes under the receiver-fixed owner, compiler subject
  validation, and an ipcache identity and Pod UID match for every address (`pkg/ztunnel/xds/effective_sources.go`).
- Conflicting claims are refused per source.
- The metric `cilium_ztunnel_xds_effective_policy_sources{origin=node|cluster|peer}` counts admitted callers.

Rules that still bind:

- The compiler supports a narrow TCP L4 subset. Unsupported egress, L7, FQDN and CIDR shapes are refused, never
  approximated.
- A service-account identity cannot separate two Pods with different policy labels. The compiler therefore emits
  one rule per source Pod that matches the exact principal, the source Pod addresses, the destination addresses and
  the ports. It emits no principal-only approximation (`pkg/policy/ztunnel_l4.go:284`, `:371-374`).
- The receiving ztunnel checks the authenticated source principal and the original destination before it opens the
  application connection. Port 15008 is transport only. Allowing it does not allow port 80.
- With `REQUIRE_INBOUND_MTLS=true`, a protected workload with no effective ALLOW policy is denied
  (`src/state.rs:762-768` in the ztunnel fork). The upstream default, which allows when no ALLOW policy exists, does
  not apply to protected workloads.
- With `REQUIRE_MESH_HBONE=true`, an unknown destination inside the configured mesh ranges is refused, and other
  egress needs an explicit exception (`src/proxy/outbound.rs:787-803`). Both flags are set in the deployed DaemonSets.

Open (from the [ADR-010 review](adr/ADR-010.md), not yet fixed):

- One compromised agent can make every reader of its cluster's leases invalid.
- Expiry starts when a record is received, so a reader restart plus a partition allows up to two lease TTLs.
- Narrowed egress can take up to 30 s to reach other destinations, not 5 s.
- More than 64 sources, 512 cuts or 4,096 ports makes a destination deny every caller.

## Traffic admission and observation

Admission for a workload requires all of these, for the **same workload UID, incarnation and configuration
generation**:

1. Platform classification permits enrollment, and Cilium holds the workload in quarantine until release.
2. The workload SVID and the required trust data are valid and used by the actual proxy.
3. The local and remote identity records are authenticated, current and unambiguous.
4. Every required policy is present and acknowledged. A missing reference fails closed.
5. Where the profile requires it, WireGuard or IPsec state is ready. No lab profile requires it today.

Independent xDS type ACKs are not a transactional barrier by themselves. The Cilium fork releases a workload from
quarantine only after the compiled plan is acknowledged on the current ADS stream, and only while every plan that
admits it as a caller is current (`callerPlansCurrent`, `pkg/ztunnel/xds/effective_policy.go:285`). Restart,
reconnect, NACK, missing references, removal and stale policy must keep that hold. Recovery on the deployed build has
not been run.

Observations that CMTC consumes bind node, proxy, workload and namespace UIDs, versions, intent generation, trust and
policy digests, capture state, admission state, time and reason to an authenticated observer. Absent or stale
evidence is Unknown or Blocked. ACKs and namespace labels never set `Protected`. Positive and negative traffic tests
validate the claimed path.

## eBPF measurement plane

Decision: [ADR-005](adr/ADR-005.md) (operator mandate 2026-10-25; status Proposed). It replaces the earlier
"temporary CMTC DaemonSet eBPF prototype" direction.

**Roles.**

| Role | Owner | Where |
| --- | --- | --- |
| Packet verdicts, service translation, native policy, workload quarantine | Cilium agent | `bpf/lib/ztunnel_admission.h`, `pkg/endpoint/ztunnel_policy*.go` in the fork |
| Workload TLS and delivered authorization | ztunnel | ztunnel fork |
| Per-node observation of datapath, enrollment, capture, authorization, TLS shape, withdrawal and recovery | CMTC eBPF measurement plane | CMTC node DaemonSet, separate measurement loader container |

The two roles never share a program, a map or a decision.

**What the measurement plane may do.**

- Every program returns the hook's pass verdict on every path: `TCX_NEXT` at TCX, allow at cgroup socket hooks.
  Tracepoints and `sock_ops` have no verdict.
- No program modifies a packet or socket, redirects traffic, or writes a map that Cilium or ztunnel reads.
- A measurement fault can lose data. It can never change traffic.
- The node agent container stays unprivileged. Only the measurement loader container holds `CAP_BPF`,
  `CAP_PERFMON`, `CAP_NET_ADMIN`, bpffs and the cgroup v2 mount.
- Discovery of enrolled workloads is node-wide and automatic. A frozen-identity mismatch makes that workload's data
  unavailable, never attributed to another workload.
- Its evidence never sets `Protected` by itself.

**TCX coexistence.** In the fork, `cil_from_container` and `cil_to_container` attach to the Pod veth through TCX
(`pkg/datapath/loader/endpoint.go`). An external TCX program is not a stable Cilium extension API. A measurement
program uses its own map and pin namespace and never replaces or reorders Cilium's links. Its position must not hide
traffic from it; the loader verifies the full chain on every sample, as the current observer does.

**Current implementation.** The CMTC source has one single-workload observer that reads `skb->len` and returns
`TCX_NEXT` (`internal/datapath/bpf/observer.c:29`). The node-wide loader is not built. Neither the observer nor the
fence is deployed in `cmtc-a` or `cmtc-b`.

**eBPF fence.** The fence returns `TCX_DROP` unconditionally (`internal/datapath/bpf/fence.c:33`). It is a lab
qualification tool for deny-path tests on disposable workloads. It is not the production gate and never becomes an
allow controller. The production gate is the native Cilium quarantine above.

**History.** The 2026-10-23 text of this section described a CMTC-first "development prototype" with a deny gate that
"belongs in Cilium's endpoint loader" in the end. That gate now lives natively in the Cilium fork. The prototype
framing is superseded; see git history of this file.

## Fork slices

| Slice | Code boundary | State, 2026-10-25 | Acceptance still open |
| --- | --- | --- | --- |
| 1. Protocol and discovery | Cilium remote exporter/importer, cluster-qualified keys, proxy protobuf pin | Implemented, deployed | Colliding names and IPs, UID recreation and unauthorized-origin records in the live lab |
| 2. Identity | SPIRE registration and attestation, proxy verifier | Implemented, deployed with per-cluster trust domains | Wrong issuer, wrong domain and cross-cluster issuance negatives, live |
| 3. L4 policy and admission | Effective-policy compiler, authorization delta stream, quarantine hold | Implemented, deployed; allow paths traffic-qualified | Stranger on port 80, allowed peer on a denied port, deny egress, missing policy, restart races, live |
| 4. Supported ClusterMesh profile | Capability check (`pkg/ztunnel/cell.go:73`) | Implemented, deployed | DNS from enrolled Pods, Global Service by name, disconnect and recovery |
| 5. Layered profiles | Independent workload and transport settings, WireGuard and XFRM | Not started | All |

Keep the CMTC work on isolated fork branches. Preserve the user's Hubble branch. Track any Rust proxy change
explicitly. Upstream messages remain a separately authorized activity.

## Acceptance matrix

The live fixture is the enrolled namespace `cmtc-live-mtls` with the negative namespace `cmtc-live-mtls-unauth` in
both clusters. `examples/apps/shop` and `examples/apps/clustermesh` remain candidate fixtures for distinct service
accounts and cross-cluster-only backends. Run each case on same-node, cross-node and cross-cluster paths:

| Test | Expected evidence | State |
| --- | --- | --- |
| Authorized source, intended port | Success, verified peer identities and policy generation | Allowed on 80, 8080, 31337 in both directions; per-connection peer evidence not recorded |
| Different SA; same SA in an unapproved cluster; wrong issuer | Denial attributable to identity policy, not only a timeout | Not run live |
| Correct peer, forbidden port | Denial despite a working HBONE tunnel | Not run live (fixture has no CiliumNetworkPolicy) |
| Same SA, forbidden Pod labels | Denial although the Pods share an mTLS principal | Not run live |
| Direct plaintext or unenrolled caller | Denial, no fallback | Unregistered caller got no response (curl timeout) |
| Missing, removed or NACKed policy; reconnect | No admission window; revocation takes effect | Not run on the deployed build |
| Pod or namespace recreation, IP reuse | Old observations cannot authorize the new incarnation | Not run on the deployed build |
| Cluster disconnect, stale export, SPIRE/proxy/Cilium outage | Bounded behavior, no downgrade; recovery keeps admission | Not run on the deployed build |
| Required WireGuard or IPsec loses state | Traffic blocks; restore needs both layers | Not applicable until slice 5 |
| API, DNS TCP/UDP, webhooks, platform workloads | Platform health intact | **Failing:** DNS from enrolled Pods times out |

Keep packet captures, authenticated connection and policy decisions, and transport state beside machine-readable
assertions. A capture alone does not prove the caller was authorized. A screenshot does not replace an assertion.
The full matrix and its results are in the [security and failure test matrix](SECURITY_AND_FAILURE_TEST_MATRIX.md).

<details>
<summary>Historical protocol and transport groundwork (2026-10-23)</summary>

[Cilium fork PR #1](https://github.com/ephico2real2/cilium/pull/1) started the protocol portion with the exact
`cilium/ztunnel` v1.0.0 Authorization schema, a separate Go security package, an independent wire fixture and
reproducible generation tests. [Focused CI passed](https://github.com/ephico2real2/cilium/actions/runs/40022647528) at
`636e441044379d48db0686eb21becf9351f782f6`. [Cilium PR #6](https://github.com/ephico2real2/cilium/pull/6) implemented
the agent-local Authorization transport lifecycle through the delta engine and a typed Hive cache.
[CI 40052995200](https://github.com/ephico2real2/cilium/actions/runs/40052995200) and local Linux ARM64 each passed
150 race-enabled tests and subtests. Those PRs had no effective-policy producer or admission gate. Their results are
protocol tests; they do not qualify the current build.

</details>
