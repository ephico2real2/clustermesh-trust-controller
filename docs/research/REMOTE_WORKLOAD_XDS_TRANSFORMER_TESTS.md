# Regression tests for remote Workload xDS mapping

This note refines the submitted `transformer_test.go` proposal for [issue #18](https://github.com/ephico2real2/clustermesh-trust-controller/issues/18). It is linked to the implementation design in [issue #16](https://github.com/ephico2real2/clustermesh-trust-controller/issues/16), scrape qualification in [issue #17](https://github.com/ephico2real2/clustermesh-trust-controller/issues/17), and observability contract in [issue #15](https://github.com/ephico2real2/clustermesh-trust-controller/issues/15).

The code sample in the request is not a compilable suite for the pinned Cilium tree. This document records the corrected contract and placement. The actual type and function signatures must be finalized beside the mapper when issue #16 implements the real extension point.

## Pinned-source test location

At Cilium source `f142e58d06a458b72cf7ea27999c093ca87c9c2b`, the current conversion is in `pkg/ztunnel/xds/endpoint_event.go`; existing tests are in `pkg/ztunnel/xds/endpoint_event_test.go`. That code emits generated `pkg/ztunnel/pb.Address` and `pb.Workload`, not `ambient.LocalWorkload`. There is no `pkg/ambient/mockbridge` package, `MockController`, `RemoteWorkloadMock`, or `CiliumIdentity` Workload field at this source pin. Use the real mapper package and test conventions rather than adding an empty package for the proposed test command.

The relevant existing package test command is:

```bash
go test -v ./pkg/ztunnel/xds
```

Run it in the documented Podman Linux build environment for local Cilium qualification. Once a remote mapper is added, narrow commands only if they select the actual changed tests; retain the full package run for acceptance.

## Defects in the submitted test suite

- The imports are placeholders (`"://github.com"`) and do not compile.
- It assumes unimplemented types and fields, including `ambient.LocalWorkload`, `Workload.CiliumIdentity`, and a logrus-backed `MockController`.
- `net.IP([]byte{999, ...})` is an invalid Go byte literal because 999 is outside the range 0–255. Prefer typed `netip.Addr` fields or a malformed input string passed through the parser under test.
- The success test treats mock-provided `ClusterName` and `SpiffeID` strings as authoritative cluster/trust identity. A string is not evidence that a peer or certificate chain was verified.
- Returning a workload with trust domain `denied.invalid` on missing SPIFFE ID does not prove ztunnel drops it. The transformer should return an error and no resource for a missing or invalid verified identity.
- An input-validation error is not a policy denial. The test must verify that no actual authorization-denial counter was incremented.
- The command `go test ./pkg/ambient/mockbridge/...` targets a package that does not exist in the inspected source.

## Test boundary

Exercise two distinct layers:

1. **Identity/provenance verification:** use a test CA and signed test SVID/peer credentials to prove that the remote cluster and workload identity are accepted or rejected by the real verification boundary. Do not set a boolean `verified` in untrusted input and treat it as proof.
2. **Pure xDS serialization:** pass only the typed verified result from that boundary into the mapper. Assert the generated protobuf fields and fail-closed behavior. Keep xDS stream send/ACK/NACK/reconnect tests separate from pure conversion tests.

A missing or invalid identity must yield `error != nil`, `resource == nil`, and zero resources sent. It must not produce a fallback trust-domain string, increment a policy-denial metric, or count as a successful fixture injection. Subsequent valid input must still be accepted so one bad record does not poison the stream.

## Required test cases

| Group | Cases | Required assertions |
| --- | --- | --- |
| Valid mapping | Authenticated IPv4, IPv6, and dual-stack workload | Non-nil `pb.Address` with Workload oneof; expected `uid`, `cluster_id`, namespace, service account, verified trust domain, HBONE, and exact `Addr.AsSlice()` bytes |
| Identity checks | Missing/malformed SVID; bad signature/issuer; wrong trust domain, namespace, service account; unknown cluster or wrong peer binding | Error, no serialized/emitted resource; bounded validation outcome only; no policy-denial count |
| Address checks | Empty set, malformed input, wrong family, unspecified, loopback, multicast, link-local, duplicates | Entire remote resource rejected under strict policy; no partial publication |
| Identity uniqueness | Same namespace/name and service account across two clusters; Pod replacement with new UID | Distinct stable resource UIDs from verified cluster plus workload incarnation; REMOVE targets the exact prior resource |
| Serialization | Protobuf marshal/unmarshal round trip | Resource key and security-relevant fields remain unchanged |
| Delta stream | ADD, update, REMOVE, stale update, NACK, timeout, disconnect/reconnect, replay | Correct resource set and nonce/ACK lifecycle; stale or rejected data does not become active; reconnect requires fresh receipt |
| Recovery | Invalid record followed by a valid record; source recovery after transient error | Stream continues safely; valid record becomes visible only after all required gates |
| Metrics | Validation failure, send failure, ACK, NACK, actual policy deny | Each counter is tied to its event; validation failure never increments enforcement-denial telemetry |

## Table-driven test shape

The following is an **illustrative shape**, not copy-ready code: the `VerifiedRemoteWorkload` type and `remoteWorkloadToAddress` function do not exist yet and must be defined against the issue #16 implementation. Keep the verified type package-private or otherwise unforgeable by the ordinary remote payload path.

```go
tests := []struct {
    name    string
    input   VerifiedRemoteWorkload
    wantErr bool
}{
    {name: "valid ipv4", input: validV4Fixture()},
    {name: "missing identity", input: missingIdentityFixture(), wantErr: true},
    {name: "namespace mismatch", input: namespaceMismatchFixture(), wantErr: true},
    {name: "untrusted peer", input: untrustedPeerFixture(), wantErr: true},
    {name: "invalid address", input: invalidAddressFixture(), wantErr: true},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        got, err := remoteWorkloadToAddress(tt.input)
        if tt.wantErr {
            require.Error(t, err)
            require.Nil(t, got)
            return
        }
        require.NoError(t, err)
        require.NotNil(t, got)
        require.NotNil(t, got.GetWorkload())
    })
}
```

The valid fixture should be produced through the same verification path or a package-private helper that cannot be reached from the normal remote payload decoder. Test certificate verification with actual signed fixtures separately. A unit test around a forged internal verified type alone proves only serialization behavior, not trust.

Use standard `testing` and Cilium's existing `testify/require` convention. Prefer a pure mapper with no logger/metrics dependency; inject metrics only at the event owner that actually observes send/ACK/NACK or enforcement. For failures in stream tests, assert emitted resources and metric deltas, not just the returned error.

## Local qualification and evidence

1. Run `go test -v ./pkg/ztunnel/xds` and applicable focused tests in the Podman Linux build environment. Confirm changed tests were selected, report pass/fail/skip counts, and preserve failure logs.
2. Run relevant race tests, required lint and vet; do not accept zero-selected tests or lint exceptions for newly changed code.
3. Build and deploy the exact Podman-built Cilium image into the existing owned two-cluster kind lab. Record source SHA, image ID and deployed node image digests.
4. Exercise valid and invalid remote records, stream recovery, positive workload mTLS and unenrolled/untrusted negative traffic. Correlate xDS, proxy identity, policy, packets and Prometheus evidence.
5. Use [the scraping plan](CILIUM_AGENT_METRICS_SCRAPING.md) and existing dashboard query evidence. Take Grafana screenshots only after representative load. CI remains deferred until local gates pass.
