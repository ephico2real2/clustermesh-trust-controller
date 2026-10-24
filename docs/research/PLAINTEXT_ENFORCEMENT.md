# Plaintext admission: Linkerd, Istio ambient and CMTC

Reviewed 2026-10-23 against the sources below. This follows the reproduced
[plaintext bypass, issue #8](https://github.com/ephico2real2/clustermesh-trust-controller/issues/8)
and supplements [the pinned mesh comparison](MESH_MTLS_COMPARISON.md).

## Deployment boundary confirmed by the user

No application sidecars. Retain the node-level ztunnel and CMTC DaemonSet.
CMTC manages policy/configuration, inventories workloads and verifies applied
state. Ztunnel terminates workload TLS; Cilium owns interception and network
policy. The CMTC inventory agent does not currently encrypt application traffic.
WireGuard/IPsec remain the separate node transport layer in the target design.

The user-supplied [Linkerd tutorial](https://oneuptime.com/blog/post/2026-01-26-linkerd-mtls/view)
uses sidecar injection, then introduces explicit Server/authentication policy.
We adopt the separation of trust, authenticated identity, destination permission
and verification. We do not install Linkerd or copy its sidecar deployment.
Technical conclusions below use project documentation/source as authority.

## What the reference meshes actually enforce

| System | Automatic encrypted path | Rejection of unauthenticated input | Enforcement owner |
| --- | --- | --- | --- |
| Linkerd | Meshed proxies authenticate workload identities | Default inbound policy is `all-unauthenticated`. `all-authenticated`, or a Server with AuthorizationPolicy requiring MeshTLSAuthentication, restricts input to mesh identities; exact identities further restrict callers. | Receiving workload proxy |
| Istio ambient | Node ztunnels establish HBONE mTLS | PeerAuthentication `STRICT` rejects plaintext. AuthorizationPolicy separately constrains principals and original destination ports. No selected authorization policy is not a deny-all. | Receiving node ztunnel |
| Current CMTC spike | Two local-node ztunnels use SPIRE SVIDs | Native authenticated-only policy rejects tested unenrolled/host paths on 80/8080/9443, including bounded restart trials. Missing-policy and first-packet admission remain unqualified. | Receiving node ztunnel, with Cilium policy publication; persistent admission still needed |

Sources: [Linkerd inbound policy reference](https://linkerd.io/docs/reference/authorization-policy/),
[automatic mTLS](https://linkerd.io/docs/features/automatic-mtls/),
[Istio ambient L4 policy](https://istio.io/latest/docs/ambient/usage/l4-policy/),
[PeerAuthentication reference](https://istio.io/latest/docs/reference/config/security/peer_authentication/).
An application speaking HTTP to its local proxy is expected. The failed case is
an unauthenticated network peer reaching a destination that should require mTLS.

Istio's 1.31.3 compiler, pinned at
`edd80bca5f71bd564711ef43ccd085acb545a6b4`, converts strict authentication into
L4 DENY rules matching an absent authenticated principal and attaches the
applicable policy to workloads. It also handles original-port exceptions and
inheritance. [Compiler](https://github.com/istio/istio/blob/edd80bca5f71bd564711ef43ccd085acb545a6b4/pilot/pkg/serviceregistry/ambient/authorization.go#L235-L303).
This is a useful model, not directly compatible generated code: Cilium's pinned
proxy uses the older authorization protobuf shape documented in the comparison.

## Can CNP or CCNP close the bypass?

They can supply a network admission boundary, but they cannot alone prove a
peer's TLS identity. Cilium's current documentation says encrypted traffic
leaves the pod before L4 enforcement, so policy generally sees HBONE TCP 15008
rather than the inner application port. Opening 15008 is not proof of mTLS.
The same documentation retains the ClusterMesh incompatibility and TCP-only
limitation. [Cilium ztunnel limitations](https://docs.cilium.io/en/latest/security/network/encryption-ztunnel/#limitations).

A candidate experiment selects only the fixture server, permits HBONE from the
fixture sources and leaves direct application ingress denied. Repeat with an
explicit port-80 deny and with a CCNP scoped to the identical namespace/pod
selector. CNP is namespace scoped; CCNP can express the cluster-managed version
without selecting every workload. [Policy types](https://docs.cilium.io/en/stable/network/kubernetes/policy/).

A plain default-deny plus allow rule is additive: an unrelated broad allow can
reopen direct HTTP. Explicit Cilium deny rules take precedence over allows,
including Kubernetes NetworkPolicy. A deny of port 80 protects only that known
port; it is not a general arbitrary-port admission solution.
[Deny precedence](https://docs.cilium.io/en/stable/security/policy/deny/).

Host-origin and host-network traffic need separate analysis. Cilium's localhost
behavior and host firewall are distinct from ordinary workload selectors;
blanket host denial can break API/kubelet/platform traffic. Preserve narrowly
validated health probes. Istio explicitly documents probe handling and HBONE
network-policy coexistence; its CNI-specific probe mechanism cannot simply be
copied into Cilium. [Cilium L3/localhost rules](https://docs.cilium.io/en/latest/security/policy/layer3/),
[host firewall](https://docs.cilium.io/en/latest/security/host-firewall/),
[Istio network-policy coexistence](https://istio.io/latest/docs/ambient/usage/networkpolicy/).

Cilium's separate `authentication.mode: required` mechanism performs agent
mutual authentication outside the application connection. It is not a substitute
for the ztunnel workload TLS session or its destination authorization contract.
[Mutual authentication architecture](https://docs.cilium.io/en/stable/network/servicemesh/mutual-authentication/mutual-authentication/).

## Implementation direction — proposed, not yet a security guarantee

1. CMTC produces explicit authenticated-only intent for eligible destinations;
   exclusion from enrollment does not grant access to a protected destination.
2. Cilium supplies destination policy references and a versioned effective
   Authorization stream. Ztunnel requires an authenticated principal and checks
   the original application target plus allowed identity. Preserve finer Cilium
   pod-label permissions; service-account identity must not broaden an allow.
3. Keep protected traffic denied while capture, identity, policy or required
   references are absent, including proxy restart and reconnect. ACK ordering
   alone cannot cover missing policy or first-packet races.
4. Use narrowly scoped CNP/CCNP as an additional network boundary only after the
   packet-path experiment passes. Handle policy coexistence, same-node sources,
   host paths, Service/Pod IP and platform probes explicitly.
5. Keep Strict/Protected unavailable until the negative matrix passes. Remote
   identity/discovery and HBONE over WireGuard/IPsec require later separate
   ClusterMesh qualification; do not remove the guard to make a test install.

Local experiment results and immutable evidence are linked from
[SPIRE_SPIKE.md](../development/SPIRE_SPIKE.md). The Grafana spike view reports
native TCP counters and observed principals, not invented handshake/protection
metrics. Positive screenshots cannot close issue #8.

## Local packet-path experiment — observed results

On the isolated two-node fixture, five stages each checked six paths. Enrolled
clients used both Service and Pod IP; unenrolled pods ran on the server's node
and the other node; host-origin HTTP ran from both kind nodes. Each HTTP 200 is
an actual response; blocked cases timed out rather than returning HTTP 403.

| Applied fixture policy | Enrolled Service / Pod IP | Unenrolled same / other node | Server-node / other host |
| --- | --- | --- | --- |
| None | 200 / 200 | 200 / 200 | 200 / 200 |
| CNP: allow HBONE, default deny other ingress | 200 / 200 | blocked / blocked | **200** / blocked |
| Same CNP + broad Kubernetes NetworkPolicy allow | 200 / 200 | **200 / 200** | **200 / 200** |
| CNP + explicit port-80 deny, broad allow retained | 200 / 200 | blocked / blocked | blocked / blocked |
| Equivalent scoped CCNP + explicit port-80 deny, broad allow retained | 200 / 200 | blocked / blocked | blocked / blocked |

All temporary policy/probe resources were removed after the experiment. The
explicit port deny is promising for network admission, including the tested
host path, but this does not establish arbitrary-port coverage, authenticated
caller authorization, safe platform exceptions, first-packet/restart behavior or
cross-cluster protection. It does not change the Observe-only CRD schema.


## Direction confirmed after the port-80 experiment

The user requires enforced workload mTLS independently of unpredictable
application ports. CNP/CCNP port denies are diagnostic experiments, not the
selected solution. The follow-up fixture exposed listeners on 80, 8080 and 9443,
plus Service 18080 → target 8080. With a port-80 deny and an additive broad allow,
plaintext on 8080/9443 still returned HTTP 200. Broad range denies also disrupted
Service paths in that fixture and are not a qualified mitigation. All temporary
experiment resources were removed.

The active Cilium implementation publishes a native GLOBAL DENY for an absent
verified principal, with no destination-port predicate. Source
`f052d1276b0fb1619809db0059fbbb7898c9cfae` is local-only; configuration/ADS race
tests, vet, pinned lint and chart checks pass. The host Podman image is built and deployed in the isolated fixture. All 57 steady/post-restart path checks passed, with 1,398 continuous restart probes returning no HTTP response, 6,000/6,000 authenticated HTTP 200 responses and 900/900 unauthenticated load attempts rejected. Native plaintext RBAC receives
no authenticated identity, so source IP metadata cannot manufacture one.
[The pinned plaintext handler](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/proxy/inbound_passthrough.rs)
performs this check before forwarding. The known default-allow behavior while
policy is missing still requires a persistent admission solution.

The separate [EP10 Envoy epic spike, issue #9](https://github.com/ephico2real2/clustermesh-trust-controller/issues/9)
compares node-level Envoy against this native path. Envoy can update credentials
through SDS and require client certificates at TLS termination. Passthrough and
termination/re-origination have different identity boundaries; preserve verified
workload identity and capture rather than substituting a node/proxy principal.
[Envoy SDS](https://www.envoyproxy.io/docs/envoy/latest/configuration/security/secret),
[client-certificate enforcement](https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto).

[Native-policy runtime evidence and both-theme Grafana captures](https://github.com/ephico2real2/clustermesh-trust-controller/blob/1c192a5ee84fb5218cb1385fdd9c5bf45ca69e1a/2026-10-24T0509Z-local-authenticated-only-f052d127/README.md) retain all 57 checks, continuous probes, load and native verdict output. Missing-policy and first-packet guarantees remain unqualified.
