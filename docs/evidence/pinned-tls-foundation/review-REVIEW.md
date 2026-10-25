# Security review: pinned TLS constructor foundation

Reviewed the complete proposal files and patch in `/private/tmp/cmtc-pinned-tls-proposal`, the prior binding `/private/tmp/cmtc-mtls-revised-review/REVIEW.md`, and corresponding source at clean `/private/tmp/cmtc-ztunnel-upstream` commit `1db4fb296beb4ca4c6c12762c61d1730dc38ceab`. The exact Cargo.lock dependency is rustls0.23.43; its cached source was inspected directly. Source checkout remains clean and unchanged. No Rust build, format, lint, handshake test, image, cluster, CI or publication operation was executed by this review.

**Disposition:** Fix server resumption before accepting this foundation. The peer verifier ordering otherwise provides the intended narrowly scoped direct-issuer authentication. This remains an isolated constructor increment with no production proxy/pool callers, authenticated profile producer, post-handshake peer-root CRL registration, Cilium provenance/policy or ClusterMesh qualification. The compatibility guard stays closed.

## P1: Server defaults allow resumed inbound connections to bypass current CRL verification

Candidate `certificate.rs:437` leaves ServerConfig defaults intact. Exact rustls0.23.43 `src/server/builder.rs` installs `ServerSessionMemoryCache::new(256)` under std and `send_tls13_tickets: 2`. `src/server/tls13.rs:350` restores the cached `client_cert_chain` and selects `full_handshake=false` when resuming. Such a handshake does not run the new inbound certificate verifier again. This matters even though our new outbound constructor disables its own resumption: another client can enable its cache and retain server-issued stateful tickets.

Therefore a reconnect after loading a client-revoking CRL can authenticate from cached state rather than current `PinnedTrustDomainVerifier`. This is source-established behavior, not a claim that an exploit test was executed. TLS1.2 is also selectable through TLS12_ENABLED, so the boundary must not rely on today's default disabled stateless ticketer.

`FIXES.patch` explicitly installs `NoServerSessionStorage`, zeroes both normal/requested TLS1.3 ticket counts, disables early data, and supplies a private `ProducesTickets` implementation that never encrypts/decrypts/enables tickets. This closes both stateful and stateless resumption independent of current provider defaults.

The added config-reuse test enables an independent client's cache deliberately. Two real application exchanges must both report Full/FullWithHelloRetryRequest rather than Resumed. It then updates the live CRL manager and requires an intended-side certificate-revocation error on the next connection using the **same Arc server/client configs**. Static assertions also lock all resumption controls. Primary should run its applicable TLS1.2-enabled profile as well as the default TLS1.3 profile; this review did not execute either.

## P2: Public current-signer helpers omit organizational-root time bounds

`current_unfenced_signer` and `current_signer_ders` filter issuer-pin time/fencing but not the organizational root's validity. The current `pinned_chain` first calls `verify_peer_evidence`, whose `current_pins` checks root validity, so this is **not a demonstrated bypass of the current handshake path**. It is an inaccurate public current-signer contract and a future call-site hazard.

The patch resolves a specific signer through `current_pins(domain, now)` and makes the all-domain hint list empty outside the root's encoded validity. A dated-root regression uses a still-valid issuer and checks both before-root-validity and exact root-expiry boundaries. Retired domains already fail correctly: retire_domain removes their `by_domain` entry; the new helper does not search other domains. Withdrawn keys are filtered and removed; no organizational-root fallback was found.

## Validation gap: Existing CRL recovery tests rebuild configurations

The proposed inbound and outbound tests call load_crl, then `exchange`, which constructs fresh verifiers/configs. They establish current-manager behavior in a newly constructed config but would also pass a faulty implementation that snapshotted CRLs at construction. The new test retains identical Arc configs and one manager across valid → revoked → signed-empty-CRL valid for both intended verifier sides. It uses an issuer-signed empty CRL with CRL number2 after the revoking number1 and confirms the manager retains one actual CRL.

A final, separately named/commented blank-file phase preserves the existing optional-CRL semantics (empty manager set) without presenting it as cryptographically signed empty-CRL recovery or authenticated CRL publication. Those are different evidence. The patch does not silently change UnknownStatusPolicy::Allow or ExpirationPolicy::Ignore inherited from verify_cert_chain.

## Other acceptance checks

- Mandatory publication and exact direct-domain issuer lookup are present. Duplicate signer keys are rejected globally. A peer's SAN must be exactly one canonical SPIFFE URI with validated domain/namespace/service account. Unknown, malformed or duplicate SANs cannot fall back to local roots.
- The first pass verifies the role-specific direct issuer and bounded root/pin/leaf time; the second pass rechecks the same pinned issuer with the current manager CRLs. Outbound compares the exact expected identity; an empty expected vector rejects every peer. Inbound authenticates any current published domain; it does **not** authorize a destination/policy.
- Both custom verifiers delegate TLS1.2/TLS1.3 handshake-signature checks to the selected real provider and advertise its schemes. They do not replace CertificateVerify proof with an assertion. Explicit inbound offer_client_auth/client_auth_mandatory both return true.
- Negative helpers await both spawned sides within a timeout, assert errors from the intended verifying side and then inspect expected certificate/anchor messages. Wrong issuer, no client certificate, role EKU and revocation checks target the intended inbound/outbound verifier. First-pass EKU/leaf-time errors are deliberately collapsed to UnauthorizedIssuer, so error wording is less specific but no acceptance bypass was found.
- The original helpers detach spawned tasks if their outer timeout itself fires, because dropping JoinHandles does not abort Tokio tasks. This is test failure hygiene rather than a production bypass; the new helper directly joins unspawned futures, so timeout cancellation cannot leave its tasks running. The primary may align the older three helpers similarly if timeout failures occur.
- The withdrawal test accurately says new_config_rejects_withdrawn_pin. Publications are immutable Arc snapshots. Already-created configurations keep their previous snapshot; existing streams/pools are unaffected. Nothing here proves live trust withdrawal or active connection draining.

## Local certificate versus publication.local_domain

The constructors currently validate **peers**, not their own workload certificate against publication.local_domain. The positive fixture deliberately passes one local-domain-A publication to both an A client and a B server. This authenticates both peers correctly because both domain pins are in that publication; it does not establish that a production node's credential/profile was bound to its configured cluster/domain.

This is an explicit missing producer/caller invariant rather than evidence of a peer-authentication bypass in this bounded API. Enforcing local identity now would change the constructor contract and invalidate intentional wrong-role/identity verifier fixtures before the intended side runs. Production integration must validate local SVID identity, namespace/service-account/cluster provenance, issuer and validity against an authenticated role-correct publication. Use separate local-domain-A/local-domain-B publications in its integration tests. Do not describe the current same-publication loopback fixture as proving local cluster/profile binding. No automatic profile rebinding or acceptance relaxation is proposed in this review.

## Fix artifact and verification boundary

`FIXES.patch` applies **after** the candidate patch, against the candidate file versions; `git apply --check` succeeded in `/private/tmp/cmtc-pinned-tls-proposal/files`. `certificate.rs` and `domain_anchors.rs` are complete corrected comparison files; `additional-tests.rs` contains the final new helper/test block. Do not copy a comparison file over newer primary changes without reviewing the diff.

Primary must apply/review, rustfmt, compile, run the focused loopback/config-reuse tests, complete library suite and strict clippy in the pinned Podman environment. These added Rust tests are uncompiled and unexecuted proposal code. Passing them would qualify only the constructor foundation; authenticated issuer-profile production, current peer-root registration, concurrent CRL reload/register race handling, real relay/pool cancellation, fresh remote Cilium identity/policy, fail-closed admission/recovery, exact images and actual cross-cluster mTLS remain separate acceptance gates.
