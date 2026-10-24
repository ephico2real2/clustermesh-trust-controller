# Primary issuer-pin review

The complete proposal is not accepted for live use. Source: `CLUSTER_TRUST_IMPLEMENTATION.md`, written against ztunnel `8106c026621a6bbf51fbd9190585e6d3549aa527`. The primary has not copied or compiled it. Review findings from the independent source reviewer require these corrections:

1. `DomainPin` exposes independently caller-controlled DER, SPKI and expiry. `try_new`/`restore_domain` must not accept a root DER concealed behind a fabricated non-root SPKI. Derive metadata from strictly parsed certificate bytes; keep fields private and use checked constructors.
2. Trust-anchor validity is not automatically the same as leaf validity. Do not let a caller's `not_after` extend the encoded authority expiry; validate encoded bounds and separate profile freshness limits. Reject non-CA anchors and invalid signing key usage. Reject trailing DER bytes.
3. `admit_domain_authorities` must not accept and return a substitute certificate merely because its public key matches an approved certificate. Return canonical approved DER and reject unauthorized subject, constraints or expiry substitutions. Pins come from authenticated configuration, never from the incoming bundle.
4. The existing certificate identity helper filters URI values it cannot parse. A strict verifier must examine the complete SAN extension and reject malformed, multiple or unsupported identity ambiguity according to an explicit supported profile. One surviving valid SPIFFE URI must not hide another malformed URI.
5. Preserve the earlier review requirements: full native policy predicates, immediate authoritative issuer withdrawal independent of SPIRE refresh success, active/pooled flow expiration, and no claim that ordinary TLS 1.3 packet capture exposes certificate plaintext.

Provide complete replacement code and executable negative/recovery tests against the real crate APIs. No placeholders, non-existent traits or omitted helper corrections. Keep the compatibility guard unchanged. Unit-level issuer checks do not qualify live handshake, source provenance, authorization, durable recovery or cross-cluster workload mTLS.
