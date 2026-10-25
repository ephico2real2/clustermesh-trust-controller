# Local pinned workload TLS foundation

The ztunnel fork now has explicit inbound/outbound rustls constructors that
verify each peer against the approved direct issuer for its SPIFFE trust
domain. They require client certificates, exact expected outbound identities,
current certificate/issuer validity and role EKU. Local SPIRE roots and the
organizational root are not fallback peer authorities. The existing production
proxy callers still use the earlier constructors; this increment is isolated.

Source is `ddb255de68cd458945f831cb1ab66f2f3f135d0c`, based on canonical
`cilium/ztunnel` master `9a17cb0ff35c20977100de3582c1e4435360f618`.
The local branch includes that upstream tip; nothing was pushed.

## What passed locally

The namespace-capable ARM64 Podman profile passes 440 distinct full-suite
tests, zero failures/ignored cases, formatting and strict Clippy. Twenty tests
were added over the previous 420-test foundation. Real TCP loopback handshakes
cover valid peers and bidirectional application bytes, foreign issuers sharing
a root, anonymous clients, malformed/duplicate identities, unknown domains,
wrong/empty expected identities, expiry, role EKU and revocation/recovery.

Pinned server configurations explicitly disable stateful and stateless session
resumption, TLS1.3 tickets and early data. Both verifier directions reuse the
same configuration objects across valid connections, CRL revocation and recovery
with an issuer-signed empty CRL. A separate optional blank-file phase records the
existing empty-CRL-manager behavior. The default test asserts TLS1.3; a separate
process forces TLS1.2 through independent peers and asserts the negotiated
version at both endpoints. Both require full verification on reconnect.

## Exact build, import and execution

The [recorded host Podman build](docs/evidence/pinned-tls-foundation/build-image.sh)
uses explicit `linux/arm64`, pinned Rust1.90 test/build tooling, bounded CPU/memory,
clean Git source and a pinned distroless base. The resulting image is
`localhost/cmtc-ztunnel:pins-ddb255de68`, configuration ID
`sha256:09207d73016a90518449b78879b1813e8dc134bc82eed899a66ae7ed6ff76880`.
Its binary reports the exact source SHA and Clean status.

The [import/verification script](docs/evidence/pinned-tls-foundation/load-and-verify.py)
archive-loads it into the existing Colima-backed `cmtc-a` and `cmtc-b`. All four
node CRI identities and ARM64 architecture match. Four temporary non-root,
PullNever version Jobs execute the exact image and pass; each is removed using
its API UID. No proxy DaemonSet or encryption setting is enabled by this check.

[Raw evidence and diagnostics](docs/evidence/pinned-tls-foundation/README.md)
include commands, exit status, source diff, tests, builds, CRI records and Jobs.
The [DaemonSet qualification](LOCAL_DAEMONSET_TELEMETRY.md) remains a separate
observation/quarantine increment.

## Open integration gates

This addresses part of CMTC-105's issuer-verification foundation. It does not
finish that story or CMTC-402/403. Production still needs an authenticated
cluster/domain/issuer-profile producer and native Cilium consumer; local SVID
and cluster binding; actual proxy/pool wiring with the peer's verified issuer
roots for post-handshake revocation; live profile withdrawal/expiry and active
flow drain; authenticated remote discovery, effective authorization, durable
admission/recovery and exact-image cross-cluster traffic evidence.

The publication is an immutable snapshot: the withdrawal test creates a new
configuration, and does not prove that existing configurations or flows update.
Inherited optional CRL unknown-status/expiry behavior is not strengthened here.
Keep those semantics explicit in the eventual production policy.

The compatibility guard stays closed. The labs still prove ClusterMesh and
application connectivity; ztunnel is disabled, and cross-cluster workload mTLS
is not qualified. CI, pushes and registry publication remain deferred.
