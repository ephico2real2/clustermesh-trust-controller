# Primary review of the workload-mTLS proposal

The first [Grok response](WORKLOAD_MTLS_DELIVERY_PROPOSAL.md) is retained for traceability. It is **not accepted or applied**. No new Rust test/build/deployment follows from this response.

The ownership findings are useful: native remote workload discovery is absent, the issuer helper is outside live TLS verification, and an unarmed retention watch cannot revoke a production pool. The ClusterMesh compatibility guard remains closed. These findings agree with the independent source audit.

Required corrections before source application:

1. Return complete applicable code, rather than placeholder method calls (`base_signature_tls12`, `base_signature_tls13`, `provider_schemes`) followed by instructions to copy the existing bodies. The response also includes a known invalid private `ServerConfig.verifier` assignment before retracting it; remove abandoned code from the corrected deliverable.
2. The pinned branches explicitly skip existing CRL validation. Adding issuer pinning cannot silently remove revocation checks. Preserve verified chain, role, exact SAN, approved direct issuer and CRL semantics, and test their composition against the real interfaces.
3. The test literal repeats `crl_manager`; this does not compile. The retention select example's `let Some(...) = ... else { pending::<()>().await }` does not provide the diverging else branch required by Rust. Argument ordering is incomplete and must match the actual `spawn_connection` signature and all callers.
4. New constructors without production callers and a watch passed as `None` by every production caller are foundations only. Do not describe them as completed handshake/pool integration. Prefer one complete, independently testable TLS-verifier increment over additional disconnected watch scaffolding.
5. Verifier method calls are not a full TLS handshake. Supply real client/server rustls handshake tests, including wrong issuer under a shared root, approved remote domain, malformed/duplicate SAN, missing/expired/withdrawn domain evidence, CRL rejection and valid recovery. Separate these from future pool/revocation and ClusterMesh acceptance.
6. The user's metric contract is part of delivery. Packet/byte/quarantine counters belong to the DaemonSet exporter; real TLS handshakes, peer validation, active connections and destination authorization belong to their actual Cilium/ztunnel boundaries. Do not alias them or mark planned telemetry implemented from proposed code. The standalone exporter scrape/dashboard increment is being implemented independently.

The corrected response must contain no unimplemented functions, placeholder imports, deliberately broken examples or unsupported security claims. Keep all accepted source unchanged until the primary has reviewed and independently qualified a coherent patch locally.
