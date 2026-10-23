# Istio and Linkerd lessons for the Cilium integration

Reviewed 2026-10-23. This is a source comparison and a proposed adaptation, not a claim that CMTC implements either mesh or that cross-cluster workload mTLS works. Deployment remains Cilium + CMTC + SPIRE/cert-manager; studying the other meshes does not add their control planes. Exact revisions and reviewed paths are in [mesh-comparison.lock.json](mesh-comparison.lock.json).

## What the limitation means

The limitation belongs to the pinned **Cilium control-plane integration**, not to the general capabilities of ztunnel. Cilium builds workload records from local CEP/CES resources and local namespace enrollment. Its mapper leaves network, trust domain, cluster ID and policy references unset, and its authorization handler returns an empty response with a static nonce. [Endpoint mapper](https://github.com/cilium/cilium/blob/beb276d2f38d4aadfda14710acf8d14a0f1ba723/pkg/ztunnel/xds/endpoint_event.go#L154-L164), [authorization handler](https://github.com/cilium/cilium/blob/beb276d2f38d4aadfda14710acf8d14a0f1ba723/pkg/ztunnel/xds/stream_processor.go#L347-L359).

The Cilium ztunnel source already subscribes to `istio.security.Authorization`. Its inbound HBONE handler replaces tunnel port 15008 with the resolved application target before constructing its authorization context; its matcher checks authenticated principals and destination ports. This gives us an existing L4 engine to integrate. Image-to-source provenance still needs verification. [Subscription](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/state.rs#L1105-L1114), [application target](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/proxy/inbound.rs#L361-L400), [matcher](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/rbac.rs#L85-L155).

## Patterns to adopt

| Concern | Reference behavior | CMTC/Cilium adaptation |
|---|---|---|
| Remote discovery | Istio builds merged local/remote ambient collections; workload records carry cluster, network, identity and policy references. | Add an authenticated remote workload export/import path; keep local ZDS/netns enrollment local. |
| Identity-aware discovery | Linkerd's destination service resolves a remote cluster through its configured cluster store and passes the remote trust domain to its endpoint translator. | Bind each imported address to an expected workload identity from the configured cluster authority. An IP or Hubble display label cannot supply that authority. |
| Destination enforcement | Istio's receiving ztunnel enforces L4 policy. Linkerd separates the target Server/port, required mesh identities and authorization binding. | Authorize the authenticated caller against the original application target. Keep existing Cilium policy effective as well. |
| Strict authentication | Automatic mTLS and rejection of plaintext are separate requirements. | Require explicit plaintext denial and test bypass paths before reporting protection. |
| Topology | Linkerd direct pod-to-pod mode preserves caller identity on a flat network; gateway mode addresses different reachability needs. | Start with directly routable ClusterMesh pod CIDRs. Qualify an east-west gateway separately if needed. |

Source anchors: [Istio global collections](https://github.com/istio/istio/blob/eed52ebb66ade45214088877b0f82855d954060d/pilot/pkg/serviceregistry/ambient/multicluster.go#L219-L285), [workload construction](https://github.com/istio/istio/blob/eed52ebb66ade45214088877b0f82855d954060d/pilot/pkg/serviceregistry/ambient/workloads.go#L708-L749), [Linkerd remote resolution](https://github.com/linkerd/linkerd2/blob/5bb8ea8434bb17a679bfcf34b2045ebeea6afcc6/controller/api/destination/server.go#L205-L225), [Linkerd target/authentication policy model](https://linkerd.io/docs/reference/authorization-policy/), [direct multicluster example](https://linkerd.io/docs/tasks/pod-to-pod-multicluster/), [Istio L4 policy and STRICT mode](https://istio.io/latest/docs/ambient/usage/l4-policy/).

Neither mesh supplies a ready-made Cilium ClusterMesh adapter. The useful reuse is their separation of discovery, identity, destination policy and traffic admission. Linkerd uses workload sidecars; ambient Istio uses ztunnel. Their deployment shapes are not interchangeable. [Linkerd mTLS](https://linkerd.io/docs/features/automatic-mtls/), [Istio ambient overview](https://istio.io/latest/docs/ambient/overview/).

## Three traps the implementation must handle

### Missing policy can allow traffic

In the pinned Cilium proxy, missing referenced policies are skipped. If the resulting ALLOW set is empty and no DENY matches, the request is allowed. A reference to a not-yet-delivered allow policy therefore cannot serve as a first-packet gate. A disconnected or restarted proxy must not admit a new protected workload while its policy is absent. [Exact evaluator](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/state.rs#L541-L634).

Proposed adaptation: a persistent fail-closed admission state for protected workloads, covering missing references and cross-resource update ordering. A bootstrap deny may help initialize a proxy, but ACK ordering alone cannot protect restart/reconnect or a later policy gap. This may require a small Rust proxy patch as well as Go/Hive work; do not assume CMTC can repair it by writing namespace labels.

### Cluster metadata does not make a cluster identity

The current proxy identity is `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`; its parser accepts that fixed path. The workload `cluster_id` field is not part of it. Identical namespace and service-account names under one trust domain are therefore the same principal across clusters. A cluster-specific intermediate under one common root does not by itself change this. [Identity parser](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/identity/manager.rs#L45-L103).

Cluster-specific trust domains are a candidate, but this proxy's inbound certificate verifier requires the peer's trust domain to match its own certificate's domain. Simply filling different `trust_domain` fields will fail the handshake. Supporting approved foreign domains needs an explicit verifier/bundle/issuer contract and negative tests; adding `/cluster/...` to the SPIFFE path also needs parser and issuer changes. [Server verifier construction](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/tls/certificate.rs#L355-L385), [trust-domain comparison](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/src/tls/workload.rs#L64-L115).

Proposed direction: evaluate per-cluster trust domains with an explicit approved-peer map, issuer restrictions and SPIRE registration/attestation bound to the originating cluster. Document the compromise boundary: an unconstrained issuer chaining to the shared root must not be treated as cryptographically limited to a cluster. Test foreign issuers issuing a locally named identity. This decision remains open in [ADR-002](../architecture/adr/ADR-002.md); no identity isolation is claimed by the Observe lab's intermediate hierarchy.

### Protocol versions and policy meanings differ

Cilium's proxy pin uses `Authorization.rules` / `Rule.clauses` / `Clause.matches`. The reviewed Istio 1.31 source uses `Authorization.groups` / `Group.rules` / `Rules.matches`, with different documented combination semantics. Do not copy the latest generated protobuf or policy compiler into the older proxy merely because the type URL matches. Pin descriptors, prove round trips and exercise AND/OR, empty-rule, DENY and removal cases. [Cilium proxy schema](https://github.com/cilium/ztunnel/blob/5bb9cf256b10a209ae9bc0624ddfbf27dbc439de/proto/authorization.proto#L22-L77), [Istio reference schema](https://github.com/istio/istio/blob/eed52ebb66ade45214088877b0f82855d954060d/pkg/workloadapi/security/authorization.proto#L23-L81).

Istio's compiler also handles unsupported HTTP predicates conservatively and surfaces warnings. CMTC should initially reject enforcement profiles whose Cilium L7 semantics cannot be preserved, while continuing Observe inventory. No HTTP method/path rule can be translated into an unrestricted TCP allow. [Istio conversion and warnings](https://github.com/istio/istio/blob/eed52ebb66ade45214088877b0f82855d954060d/pilot/pkg/serviceregistry/ambient/authorization.go#L433-L488).

## Concrete next implementation

The [Cilium integration contract](../architecture/CILIUM_ZTUNNEL_CONTRACT.md) turns these findings into component boundaries, rollout order and required negative tests. The existing copied POS/stranger and Global Service apps provide the application fixtures. Current CI validates their baseline Cilium behavior only; workload mTLS and required transport layering remain blocked until the corresponding adapters and datapath tests exist.
