# Remote workload mapping into ztunnel xDS

This design note records the fourth work item, [issue #16](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16), and the mapping proposal supplied for the CMTC-105 remote workload path. It follows the observability contract in [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15) and the test-only injection probe in [issue #14](https://github.com/ephico2real2/clustermesh-trust-controller/issues/14). The production federation objective remains [issue #13](https://github.com/ephico2real2/clustermesh-trust-controller/issues/13).

This document is a source-grounded design and test boundary, not a claim that remote Workload xDS discovery is implemented or that a mock resource establishes mTLS.

## Source audit

The inspected Cilium checkout is `/private/tmp/cilium-ztunnel-authorization-runtime`, branch `feat/ztunnel-spire-credentials`, HEAD `f142e58d06a458b72cf7ea27999c093ca87c9c2b`. At inspection time, the worktree had local modifications in the ztunnel xDS event, metrics, stream processor, and server files. Re-check the target revision and working diff before implementing against this note.

The current code uses `pkg/ztunnel/xds/EndpointEvent` and converts Kubernetes `CiliumEndpoint` data to generated `pkg/ztunnel/pb.Address` containing `pb.Workload`. The protobuf schema is `pkg/ztunnel/pb/workload_ztunnel.proto`. The submitted proposal's `pkg/ambient/mockbridge`, `ambient.LocalWorkload`, `MockController`, and `APIWorkloads` symbols do not exist at this source pin. The pasted import paths are placeholders and are not valid Go imports. Do not create a parallel “ambient” abstraction or inject synthetic remote records into the local Kubernetes endpoint cache merely to match that sketch.

`pb.Workload` includes a resource `uid`, raw IP address bytes, `network`, `trust_domain`, `service_account`, `cluster_id`, and tunnel/status fields. It does not include the proposed `CiliumIdentity` field. Existing local endpoint conversion does not verify a remote certificate chain or authenticate a ClusterMesh peer. The remote source, its trust boundary, and its place in the xDS Delta stream still need to be designed against the actual pinned code.

## Required transformation boundary

Use this conceptual flow:

```text
authenticated ClusterMesh peer
  → verify cluster binding and remote workload provenance
  → validate the verified SPIFFE identity against workload namespace/service account
  → validate workload incarnation and IP addresses
  → serialize a typed record into pkg/ztunnel/pb.Address / pb.Workload
  → publish ADD/UPDATE/REMOVE through the actual Delta xDS stream
  → record send, ACK/NACK, timeout and reconnect separately
```

The serializer may validate consistency, but it cannot turn untrusted fields into proof. A supplied cluster name, `cluster-beta.mesh`, or SPIFFE ID string is not enough to establish peer trust. The trust domain and cluster ID must come from authenticated federation configuration and verified provenance. Only pass a record produced by that verification boundary into production serialization.

For the identity tuple `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`, require the verified trust domain, namespace, and service account to agree with the authoritative cluster/workload record. Missing, malformed, unverified, or inconsistent identity must return an error and produce no xDS resource. Do not return a successful workload with `trust_domain: denied.invalid`; ztunnel rejection of that fabricated identity has not been established, and the resource could still be published.

Use a stable, collision-resistant xDS resource UID that includes the authenticated cluster identity and workload incarnation. Populate protobuf `cluster_id` from the verified peer binding. Define how replacement Pods with the same name receive different UIDs, and ensure REMOVE uses the exact UID used by ADD. A namespace/name tuple or mock-supplied cluster string is not sufficient incarnation identity.

Parse addresses as `netip.Addr` (or parse their authoritative string form), validate family and supported unicast scope, reject empty/duplicate/malformed entries, and encode bytes with `Addr.AsSlice()`. Decide explicitly whether one bad address rejects the entire workload; for the strict remote path, reject the entire record rather than silently publishing an incomplete address set.

## Why the submitted implementation sketch is unsafe to copy

- It calls types and an insertion API absent from the pinned source tree, so it is not a patch against the real Cilium architecture.
- It trusts `ClusterName` and `SpiffeID` fields provided by the mock and derives the trust domain by string concatenation.
- It builds and returns a workload when SPIFFE identity is empty, replacing the trust domain with `denied.invalid`. This does not verify identity or prove fail-closed behavior.
- It increments the proposed “injected” counter before validating the input, and misclassifies an empty identity as a policy violation. Input validation, xDS delivery, ACK/NACK and datapath policy denial are different events.
- It appends synthetic objects to an alleged local workload cache. The actual remote source and ownership lifecycle must be explicit and must not make test fixtures visible to ordinary agent operation.
- It reports a `CiliumIdentity` field that is absent from the generated ztunnel Workload protobuf.

If a mock source is retained for local xDS testing, keep it behind a test-only construction path that is disabled in normal agent operation. Feed it through the same typed validation/serialization code as the production source, but never let a fixture self-assert that its cluster binding or certificate is verified.

## Metrics and evidence

Use Cilium's existing metric registration and Hive wiring at the real event boundary. A conversion error may be counted as a bounded xDS validation failure if that metric contract is implemented. A send, ACK, NACK, timeout, and reconnect should remain distinguishable where the runtime exposes them. A malformed or missing SPIFFE identity is not an authorization denial. Count a policy denial only when the real enforcement path rejects traffic.

No protobuf, ACK, mock counter, or ServiceMonitor proves that an application connection authenticated. End-to-end acceptance still requires a real request from an identified workload, a negative unauthenticated/untrusted case, native policy evidence, ztunnel identity evidence, packet evidence, and local Prometheus query evidence. Workload TLS and node-to-node WireGuard/IPsec evidence must be kept distinct.

## Local-first acceptance path

1. Reconfirm the Cilium source base and dirty diff; identify the real remote-record source and xDS publication boundary before editing.
2. Define an authenticated input type and the source of every cluster, Pod UID, namespace, service-account, trust-domain, and address field.
3. Add a typed mapper to the generated protobuf and focused mapping/Delta stream tests. See [the refined test plan](REMOTE_WORKLOAD_XDS_TRANSFORMER_TESTS.md) and [issue #18](https://github.com/ephico2real2/clustermesh-trust-controller/issues/18).
4. Run selected Go tests, relevant race tests, lint and vet locally in the host Podman workflow. Reject zero-selected or skipped tests as evidence.
5. Build the exact Cilium image with Podman, transfer it into the existing owned two-cluster kind lab, and verify the deployed image ID/source pin.
6. Exercise positive and negative real traffic, identity and policy recovery, xDS lifecycle, packet path, and query evidence. Keep CI deferred until local gates pass.

Related scrape qualification is tracked in [issue #17](https://github.com/ephico2real2/clustermesh-trust-controller/issues/17). The validator and dashboards remain governed by the existing contract in [REMOTE_XDS_OBSERVABILITY.md](REMOTE_XDS_OBSERVABILITY.md).
