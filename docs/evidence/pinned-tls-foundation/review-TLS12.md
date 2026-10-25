# Force actual TLS1.2 in the reused-config CRL regression

Apply `TLS12.patch` after the primary's current constructor/test fixes. It checked cleanly against current `/private/tmp/cmtc-ztunnel-upstream/src/tls/certificate.rs`. `certificate-tls12.rs` is a comparison copy, not an instruction to overwrite newer source. No source edit, build or test execution was performed by this proposal.

Use the existing pinned Podman Rust environment/working directory/features/target, changing only the test-process environment and exact filter. For its existing cargo test invocation:

```sh
TLS12_ENABLED=true cargo test --locked --lib \
  tls::certificate::test::pinned_configs_recheck_live_crls_with_signed_empty_and_optional_blank_recovery \
  -- --exact --nocapture --test-threads=1
```

With host Podman, pass `--env TLS12_ENABLED=true` to that task's existing pinned `podman run` rather than modifying a host environment or any Rust process environment at runtime. Retain existing feature arguments and pinned caches. This proposal does not invent a new builder/image command.

Run the same test in a separate default profile too:

```sh
TLS12_ENABLED=false cargo test --locked --lib \
  tls::certificate::test::pinned_configs_recheck_live_crls_with_signed_empty_and_optional_blank_recovery \
  -- --exact --nocapture --test-threads=1
```

A full-suite run with TLS12_ENABLED=true is also appropriate; its general handshakes may still prefer TLS1.3, whereas this exact regression now forces and asserts TLS1.2. Neither command was run here.

Why this forces negotiation without modifying production constructors:

- The existing provider exposes repository-approved TLS1.2 suites only in the separate TLS12_ENABLED=true process. The test only reads the existing Lazy flag; it never calls set_var or changes global configuration while other tests run.
- Inbound branch uses the **actual pinned_server_config** unchanged. The independent client is built through the existing rustls/provider APIs with exactly `[TLS12]`, the same pinned peer verifier and actual client certificate. This client explicitly enables stateful/RFC5077 resumption, so server security cannot depend on our outbound helper disabling it.
- Outbound branch uses the **actual pinned_client_config** unchanged. An independent server advertises exactly `[TLS12]`, a valid cert and normal required client certificate verification. The pinned client continues to disable resumption.
- Both positive first/reconnect handshakes and signed-empty/optional-blank recovery exchanges assert `protocol_version()==TLSv1_2` on **both** endpoints, print the observed version under nocapture and retain the original Full/FullWithHelloRetryRequest assertions. The same Arc configurations and CRL manager persist through real application bytes, intended-verifier revocation rejection and both recovery forms.
- With the default flag false the exact same regression asserts actual TLS1.3; no skipped or ignored branch is counted as TLS1.2 proof. The wrapper used by the empty-expected-identity negative remains unchanged and does not force a protocol.

This is protocol-specific loopback constructor qualification only. No authenticated profile producer, post-handshake connection registration, live proxy/pool integration, Cilium discovery/policy, compatibility guard or lab mTLS activation is added.
