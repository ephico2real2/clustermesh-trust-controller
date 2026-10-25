# Cursor cross-cluster workload mTLS implementation proposal

Model: Grok 4.7 Extra High. Unaccepted until primary source review and independent local qualification.

The mTLS path is still unwired, so I’m tracing the accepted issuer helper, the Cilium xDS/admission interfaces, and the remote-discovery gap before choosing one complete increment.The handshake still accepts a certificate that chains to the shared root and matches a SPIFFE string. The accepted pin verifier is not on that path. This increment puts that verifier on the real rustls client and server checks, and teaches the HBONE driver to tear down a connection when a retention watch fires. It does not open ClusterMesh, deploy ztunnel, or encrypt the labs.

# Workload mTLS delivery proposal

Status: proposal only. Not applied, not compiled, and not run. The ClusterMesh guard stays closed. Reachability, the deny fence, and the issuer unit tests are not workload mTLS.

## What owns the path

Ztunnel owns the peer certificate decision. Cilium owns discovery, CNI admission, and the compatibility guard. CMTC owns trust configuration and must not inject identities into the proxy.

| Step | Real code | Today |
|---|---|---|
| Guard | `validateConfig` in `pkg/ztunnel/cell.go` returns `ztunnel is not compatible with clustermesh` when both are enabled | Closed. This patch does not change it. |
| Remote workload | `pkg/ztunnel/xds/endpoint_event.go` assigns `TrustDomain` and `ClusterId` from configured strings | A matching name or string is not a verified issuer or a remote inventory. |
| CNI Required | `gate.once` in `pkg/ztunnel/admission/cell.go` commits the intent journal, then enrolls | Intent and enrollment are not a TLS peer check. Namespace UID is stored and is not a grant. |
| Inbound TLS | `TrustDomainVerifier::verify_client_cert` in `src/tls/workload.rs` calls the webpki verifier, then `certificate::identities` | Any parsed URI in the local trust domain is enough. A bad extra URI is dropped by that helper. A foreign domain is rejected even when it has its own pin. |
| Outbound TLS | `IdentityVerifier::verify_server_cert` checks `self.roots`, then the first matching SPIFFE string | A chain to the organizational root succeeds for a leaf signed by another cluster's intermediate. |
| Accepted pins | `verify_peer_evidence` and `verify_expected_identity` in `src/tls/domain_anchors.rs` | Tested library. No handshake calls them. |
| Live HBONE | `drive_connection` in `src/proxy/h2/client.rs` ends on drain, ping failure, CRL, or HTTP/2 end | No anchor generation, withdrawal, or deadline is watched. `pool.rs` and the inner tunnel in `outbound.rs` only register CRL. |
| Fence | Separate CMTC TCX program | Ingress deny on one audited veth. It does not see a certificate. |

The first coherent slice is the ztunnel handshake and the HBONE driver watch. Remote discovery, SPIRE publication, pool arming, and the guard stay open because the source does not yet have an authenticated remote inventory or a loaded pin publication.

## Patch against ztunnel `1db4fb296beb4ca4c6c12762c61d1730dc38ceab`

Unpinned mode stays the current behavior, so existing callers keep compiling. Pinned mode does not treat the organizational root as success.

### `src/tls/workload.rs`

Add the import and the error map next to the existing rustls imports:

```rust
use crate::tls::domain_anchors::{self, AnchorError, DomainAnchorSet, PeerRole};
```

```rust
fn anchor_to_rustls(error: AnchorError) -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(OtherError(Arc::new(
        error,
    ))))
}
```

Replace `TrustDomainVerifier` and its `verify_client_cert` with:

```rust
#[derive(Debug)]
pub(super) struct TrustDomainVerifier {
    base: Arc<dyn ClientCertVerifier>,
    trust_domain: Option<Strng>,
    anchors: Option<Arc<DomainAnchorSet>>,
}

impl TrustDomainVerifier {
    pub fn new(
        base: Arc<dyn ClientCertVerifier>,
        trust_domain: Option<Strng>,
        anchors: Option<Arc<DomainAnchorSet>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            base,
            trust_domain,
            anchors,
        })
    }

    fn verify_trust_domain(&self, client_cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        use x509_parser::prelude::*;
        let Some(want_trust_domain) = &self.trust_domain else {
            return Ok(());
        };
        let (_, c) = X509Certificate::from_der(client_cert).map_err(|_e| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let ids = tls::certificate::identities(&c).map_err(|_e| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
        trace!(
            "verifying client identities {ids:?} against trust domain {:?}",
            want_trust_domain
        );
        ids.iter()
            .find(|id| match id {
                Identity::Spiffe { trust_domain, .. } => trust_domain == want_trust_domain,
            })
            .ok_or_else(|| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(TlsError::SanTrustDomainError(
                        want_trust_domain.to_string(),
                        ids.clone(),
                    ))),
                ))
            })
            .map(|_| ())
    }
}

impl ClientCertVerifier for TrustDomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.base.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if let Some(anchors) = &self.anchors {
            // The pin set decides the peer. The local-domain string check and
            // certificate::identities are not consulted: one valid URI must not
            // hide another SAN, and another cluster is accepted only with its pin.
            domain_anchors::verify_peer_evidence(
                end_entity,
                intermediates,
                anchors,
                now,
                PeerRole::Client,
            )
            .map_err(anchor_to_rustls)?;
            return Ok(ClientCertVerified::assertion());
        }
        let res = self
            .base
            .verify_client_cert(end_entity, intermediates, now)?;
        self.verify_trust_domain(end_entity)?;
        Ok(res)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base.supported_verify_schemes()
    }
}
```

Replace the `IdentityVerifier` struct and `verify_server_cert` with:

```rust
#[derive(Debug)]
pub struct IdentityVerifier {
    pub(super) roots: Arc<RootCertStore>,
    pub(super) identity: Vec<Identity>,
    pub(super) crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    pub(super) anchors: Option<Arc<DomainAnchorSet>>,
}

impl ServerCertVerifier for IdentityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sn: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(anchors) = &self.anchors {
            // CRL and OCSP are not acceptance inputs on this branch.
            domain_anchors::verify_expected_identity(
                end_entity,
                intermediates,
                anchors,
                &self.identity,
                now,
                PeerRole::Server,
            )
            .map_err(anchor_to_rustls)?;
            if !ocsp_response.is_empty() {
                trace!("Unvalidated OCSP response: {ocsp_response:?}");
            }
            return Ok(ServerCertVerified::assertion());
        }

        let crls: Arc<Vec<CertRevocationList<'static>>> = self
            .crl_manager
            .as_deref()
            .map(|mgr| mgr.get_crls())
            .unwrap_or_default();
        crate::tls::revocation::verify_cert_chain(
            end_entity,
            intermediates,
            &self.roots,
            now,
            KeyUsage::server_auth(),
            &crls,
        )
        .map_err(webpki_error_to_rustls)?;
        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {ocsp_response:?}");
        }
        self.verify_full_san(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base_signature_tls12(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base_signature_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider_schemes()
    }
}
```

Keep the existing `verify_tls12_signature`, `verify_tls13_signature`, and `supported_verify_schemes` bodies. The names `base_signature_tls12`, `base_signature_tls13`, and `provider_schemes` above are only placeholders in this explanation: copy the three existing method bodies unchanged onto the new `impl ServerCertVerifier`. Do not add those extra names.

Every current `IdentityVerifier { roots, identity, crl_manager }` literal gains `anchors: None`. That is `client_config` in `src/tls/certificate.rs`. `TrustDomainVerifier::new(raw_client_cert_verifier, td)` becomes `TrustDomainVerifier::new(raw_client_cert_verifier, td, None)`.

Add these methods on `WorkloadCertificate` beside `client_config` and `server_config`. They are the same constructors with the pin set attached. They do not read SPIRE and they do not change the unpinned methods.

```rust
pub fn server_config_with_anchors(
    &self,
    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    anchors: Arc<crate::tls::domain_anchors::DomainAnchorSet>,
) -> Result<ServerConfig, Error> {
    let mut config = self.server_config(crl_manager)?;
    let td = self.cert.identity().map(|i| match i {
        Identity::Spiffe { trust_domain, .. } => trust_domain,
    });
    let raw = WebPkiClientVerifier::builder_with_provider(
        self.root_store.clone(),
        crate::tls::lib::provider(),
    )
    .build()?;
    let verifier = crate::tls::workload::TrustDomainVerifier::new(raw, td, Some(anchors));
    config.verifier = verifier;
    Ok(config)
}
```

`ServerConfig.verifier` is not a public field in rustls. Do not use that assignment. Build the pinned server config directly:

```rust
pub fn server_config_with_anchors(
    &self,
    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    anchors: Arc<crate::tls::domain_anchors::DomainAnchorSet>,
) -> Result<ServerConfig, Error> {
    let td = self.cert.identity().map(|i| match i {
        Identity::Spiffe { trust_domain, .. } => trust_domain,
    });
    let raw_client_cert_verifier = WebPkiClientVerifier::builder_with_provider(
        self.root_store.clone(),
        crate::tls::lib::provider(),
    )
    .build()?;
    let client_cert_verifier = crate::tls::workload::TrustDomainVerifier::new(
        raw_client_cert_verifier,
        td,
        Some(anchors),
    );
    let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
        .with_protocol_versions(tls::tls_versions())
        .expect("server config must be valid")
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(
            self.cert_and_intermediates_der(),
            self.private_key.clone_key(),
        )?;
    sc.alpn_protocols = vec![b"h2".into()];
    let _ = crl_manager;
    Ok(sc)
}

pub fn client_config_with_anchors(
    &self,
    identity: Vec<Identity>,
    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    anchors: Arc<crate::tls::domain_anchors::DomainAnchorSet>,
) -> Result<ClientConfig, rustls::Error> {
    let verifier = crate::tls::workload::IdentityVerifier {
        roots: self.root_store.clone(),
        identity,
        crl_manager,
        anchors: Some(anchors),
    };
    let mut cc = ClientConfig::builder_with_provider(crate::tls::lib::provider())
        .with_protocol_versions(tls::tls_versions())
        .expect("client config must be valid")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            self.cert_and_intermediates_der(),
            self.private_key.clone_key(),
        )?;
    cc.alpn_protocols = vec![b"h2".into()];
    cc.resumption = Resumption::disabled();
    Ok(cc)
}
```

The `_ = crl_manager` line is intentional. The pinned server branch does not consult CRLs. Wiring them into `verify_peer_evidence` is still open. Do not pass the union `root_store` into `verify_peer_evidence`.

`src/tls.rs` already exports `pub mod domain_anchors`. No module-list change.

### Handshake tests in `src/tls/workload.rs`

Append this module. It calls `verify_server_cert` and `verify_client_cert`. The leaf is signed by the domain pin and presented with an empty intermediate list, which is what `path_accepts` requires.

```rust
#[cfg(test)]
mod pin_handshake_tests {
    use super::*;
    use crate::tls::domain_anchors::{pin_from_certificate, DomainAnchorSet};
    use crate::tls::revocation::verify_cert_chain;
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use rustls::client::danger::ServerCertVerifier;
    use rustls::server::danger::ClientCertVerifier;
    use rustls::server::WebPkiClientVerifier;

    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";

    fn ca(name: &str) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, name);
        CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
    }

    fn issued(name: &str, parent: &CertifiedIssuer<'_, KeyPair>) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, name);
        CertifiedIssuer::signed_by(params, KeyPair::generate().unwrap(), parent).unwrap()
    }

    fn leaf(uri: &str, issuer: &CertifiedIssuer<'_, KeyPair>) -> CertificateDer<'static> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params.subject_alt_names = vec![SanType::URI(Ia5String::try_from(uri.to_string()).unwrap())];
        params
            .signed_by(&KeyPair::generate().unwrap(), &**issuer)
            .unwrap()
            .der()
            .clone()
    }

    fn anchors(
        root: &CertifiedIssuer<'_, KeyPair>,
        a: &CertifiedIssuer<'_, KeyPair>,
        b: &CertifiedIssuer<'_, KeyPair>,
    ) -> Arc<DomainAnchorSet> {
        Arc::new(
            DomainAnchorSet::try_new(
                "cmtc-a.mesh.example".into(),
                root.der().clone(),
                1,
                vec![
                    pin_from_certificate("cmtc-a.mesh.example".into(), a.der().clone()).unwrap(),
                    pin_from_certificate("cmtc-b.mesh.example".into(), b.der().clone()).unwrap(),
                ],
            )
            .unwrap(),
        )
    }

    #[test]
    fn pinned_server_and_client_accept_their_domain_and_reject_the_shared_root_chain() {
        let root = ca("root");
        let a = issued("a", &root);
        let b = issued("b", &root);
        let set = anchors(&root, &a, &b);
        let leaf_a = leaf(URI_A, &a);
        let foreign = leaf(URI_A, &b);
        let now = UnixTime::now();
        let expected = vec![Identity::from_str(URI_A).unwrap()];
        let server = IdentityVerifier {
            roots: Arc::new(RootCertStore::empty()),
            identity: expected,
            crl_manager: None,
            anchors: Some(set.clone()),
        };
        assert_eq!(
            server
                .verify_server_cert(&leaf_a, &[], &"example.com".try_into().unwrap(), &[], now)
                .unwrap(),
            ServerCertVerified::assertion()
        );
        let mut roots = RootCertStore::empty();
        roots.add(root.der().clone()).unwrap();
        verify_cert_chain(
            &foreign,
            &[b.der().clone()],
            &roots,
            now,
            KeyUsage::server_auth(),
            &[],
        )
        .expect("the shared root chain is not pin acceptance");
        assert!(server
            .verify_server_cert(&foreign, &[], &"example.com".try_into().unwrap(), &[], now)
            .is_err());

        let base = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            crate::tls::lib::provider(),
        )
        .build()
        .unwrap();
        let client = TrustDomainVerifier::new(
            base,
            Some("cmtc-a.mesh.example".into()),
            Some(set),
        );
        client.verify_client_cert(&leaf_a, &[], now).unwrap();
        client
            .verify_client_cert(&leaf(URI_B, &b), &[], now)
            .expect("cluster B is a pinned peer, not a local-domain string");
        assert!(client.verify_client_cert(&foreign, &[], now).is_err());
        assert!(client
            .verify_client_cert(&leaf("spiffe://cmtc-a.mesh.example/ns/orders/sa/api", &a), &[], now)
            .is_ok());
        let mixed = {
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = IsCa::ExplicitNoCa;
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ];
            params.subject_alt_names = vec![
                SanType::URI(Ia5String::try_from(URI_A.to_string()).unwrap()),
                SanType::URI(Ia5String::try_from("spiffe://not-a-profile").unwrap()),
            ];
            params
                .signed_by(&KeyPair::generate().unwrap(), &a)
                .unwrap()
                .der()
                .clone()
        };
        assert!(client.verify_client_cert(&mixed, &[], now).is_err());
    }
}
```

The second `verify_client_cert(&leaf(URI_A...))` repeats the success case. Keep the B success, the foreign-issuer failure, and the two-URI failure. Delete the redundant URI_A call if the primary wants one success assertion.

`roots.add` in rustls 0.23 returns `Result<(), webpki::Error>` through the store. The existing `domain_anchors` code uses `roots.add(pin.der.clone()).is_err()`. Use that same call and `expect` on the `Result`.

This test establishes the rustls verifier decision for a direct pin, a shared-root foreign signer, a pinned foreign identity, and a second malformed URI. It does not establish a TCP handshake, CRL enforcement, pool drain, xDS, or either lab cluster.

### HBONE retention watch

In `src/proxy/h2.rs`, add:

```rust
    #[error("peer anchor withdrawn or expired")]
    AnchorWithdrawn,
```

In `spawn_connection`, add the argument after `revocation`:

```rust
    retention: Option<tokio::sync::watch::Receiver<crate::tls::domain_anchors::RetainedDecision>>,
```

Pass `retention` into `drive_connection`. In that function, add it beside `revocation` and add this `select!` arm before the connection arm:

```rust
        _ = async {
            let Some(rx) = retention.as_mut() else {
                std::future::pending::<()>().await
            };
            loop {
                if *rx.borrow() == crate::tls::domain_anchors::RetainedDecision::Drain {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        } => {
            teardown.set(Teardown::AnchorWithdrawn);
        }
```

`pool.rs` and `outbound.rs` pass `None` for this argument. The two existing `spawn_connection` tests in `h2/client.rs` also pass `None`. Production pools are therefore not armed.

Add this test next to `transport_failure_is_recorded`:

```rust
    #[tokio::test]
    async fn retention_watch_tears_down_the_live_hbone_driver() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((_req, mut respond))) = conn.accept().await {
                let resp = http::Response::builder().status(200).body(()).unwrap();
                std::mem::forget(respond.send_response(resp, false).unwrap());
            }
        });
        let (_drain_tx, drain_rx) = tokio::sync::watch::channel(false);
        let (retention_tx, retention_rx) =
            tokio::sync::watch::channel(crate::tls::domain_anchors::RetainedDecision::Keep);
        let mut client = spawn_connection(
            Arc::new(crate::test_helpers::test_config()),
            client_io,
            drain_rx,
            wl_key(),
            None,
            TeardownCause::default(),
            Some(retention_rx),
        )
        .await
        .unwrap();
        let (stream, _) = client.send_request(connect_request()).await.unwrap();
        retention_tx
            .send(crate::tls::domain_anchors::RetainedDecision::Drain)
            .unwrap();
        let teardown = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.teardown_cause().torn_down(),
        )
        .await
        .expect("retention watch should end the driver");
        assert!(matches!(teardown, Teardown::AnchorWithdrawn), "{teardown:?}");
    }
```

This drives `drive_connection` through `spawn_connection`. It does not call `retained_tunnel` or `apply_retention`, and the duplex stream is not a TCP socket. Both halves of a pooled TLS connection are still open in production because `pool.rs` passes `None`.

## Commands for the primary

From `/private/tmp/cmtc-ztunnel-upstream`, in the existing Linux ARM64 Podman test image. Not run here.

```sh
cargo fmt --check -- src/tls/workload.rs src/tls/certificate.rs src/proxy/h2.rs src/proxy/h2/client.rs src/proxy/pool.rs src/proxy/outbound.rs
cargo test --locked --lib pin_handshake_tests -- --test-threads=8
cargo test --locked --lib retention_watch_tears_down_the_live_hbone_driver -- --test-threads=1
cargo test --locked --lib --tests --bins -- --test-threads=1
cargo clippy --locked --benches --tests --bins -- -D warnings
```

Do not build or import an image from this patch until those commands pass. The staged image `localhost/cmtc-ztunnel:strict-1db4fb296b` does not contain it. No DaemonSet install and no lab traffic are part of this slice.

## Gates this does not close

- Cilium still copies one configured trust-domain string in `endpoint_event.go`. There is no atomic remote inventory, ordered delete, or namespace-UID provenance on the xDS path. The guard stays closed until that source exists and the exact images pass.
- Nothing loads a `DomainAnchorSet` from SPIRE or from CMTC. `server_config` and `client_config` remain unpinned. `server_config_with_anchors` and `client_config_with_anchors` have no production caller.
- Pinned verification does not apply CRLs. A withdrawn pin drains a connection only if some caller puts `RetainedDecision::Drain` on the watch. `pool.rs` and the inner `outbound.rs` tunnel do not.
- `retained_tunnel` is not called from the driver. A test that flips the watch does not prove expiry or issuer withdrawal computed that decision.
- The deny fence remains quarantine of one host-veth ingress. It is not peer authentication and this patch does not extend it.
- Protected is not a label, a ready probe, an ACK, or a passing unit test. A→B and B→A application traffic, unenrolled denial, ports 80, 8080, and 31337, restart, and optional WireGuard or IPsec still require the guard to stay closed until those exact-image runs exist.
