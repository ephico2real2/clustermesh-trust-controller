# Cursor cross-cluster workload mTLS implementation proposal

Model: Grok 4.7 Extra High. Unaccepted until primary source review and independent local qualification.

The previous patch skipped CRL and left constructors uncalled. I’m reading the live verifier, certificate, pin, and revocation interfaces so the replacement is one strict handshake path with real loopback tests.The strict handshake constructors below are a verifier increment on ztunnel `1db4fb296beb4ca4c6c12762c61d1730dc38ceab`. They always take an `AnchorPublication`, keep direct-issuer, role, exact-SAN, and CRL checks together, and leave the existing unpinned `server_config` and `client_config` paths unchanged. Nothing in the proxy, pool, SPIRE client, or Cilium xDS calls them. The ClusterMesh guard stays closed. This does not encrypt the labs, arm pool revocation, or add handshake metrics.

```diff
diff --git a/src/tls/domain_anchors.rs b/src/tls/domain_anchors.rs
index 1db4fb296b..pinned-verifier 100644
--- a/src/tls/domain_anchors.rs
+++ b/src/tls/domain_anchors.rs
@@ -102,6 +102,9 @@ impl VerifiedPeer {
         self.valid_until
     }
     pub fn retained_tunnel(&self) -> RetainedTunnel {
         RetainedTunnel(self.clone())
     }
+    pub fn signer_spki(&self) -> &[u8] {
+        &self.signer_spki
+    }
 }
 #[derive(Clone, Debug, Eq, PartialEq)]
 pub struct RetainedTunnel(VerifiedPeer);
@@ -602,6 +605,26 @@ impl AnchorPublication {
     pub fn bundle_fenced(&self, spki: &[u8]) -> bool {
         self.bundle_fenced.contains(spki)
     }
+    pub fn unfenced_signer(&self, spki: &[u8]) -> Option<CertificateDer<'static>> {
+        if self.bundle_fenced.contains(spki) {
+            return None;
+        }
+        self.set
+            .by_domain
+            .values()
+            .flatten()
+            .find(|pin| pin.spki_der == spki)
+            .map(|pin| pin.der.clone())
+    }
+    pub fn current_signer_ders(&self, now: SystemTime) -> Vec<CertificateDer<'static>> {
+        self.set
+            .by_domain
+            .values()
+            .flatten()
+            .filter(|pin| pin.current(now) && !self.bundle_fenced.contains(&pin.spki_der))
+            .map(|pin| pin.der.clone())
+            .collect()
+    }
     fn require_newer(&self, generation: u64) -> Result<(), AnchorError> {
         if generation <= self.generation() {
             return Err(AnchorError::StaleGeneration {
diff --git a/src/tls/workload.rs b/src/tls/workload.rs
index 1db4fb296b..pinned-verifier 100644
--- a/src/tls/workload.rs
+++ b/src/tls/workload.rs
@@ -31,11 +31,13 @@ use std::future::Future;
 use std::io;
 use std::pin::Pin;
 use std::sync::Arc;
+use std::time::SystemTime;
 use tokio::io::{AsyncRead, AsyncWrite};
 use webpki::{CertRevocationList, KeyUsage};
 
 use crate::strng::Strng;
 use crate::tls;
+use crate::tls::domain_anchors::{AnchorError, AnchorPublication, PeerRole, verify_peer_evidence};
 use tokio::net::TcpStream;
 use tokio_rustls::client;
 use tracing::{debug, trace};
@@ -354,3 +356,226 @@ impl ServerCertVerifier for IdentityVerifier {
             .supported_schemes()
     }
 }
+
+fn anchor_to_rustls(error: AnchorError) -> rustls::Error {
+    rustls::Error::InvalidCertificate(rustls::CertificateError::Other(OtherError(Arc::new(
+        error,
+    ))))
+}
+
+fn pinned_chain(
+    publication: &AnchorPublication,
+    end_entity: &CertificateDer<'_>,
+    intermediates: &[CertificateDer<'_>],
+    now: UnixTime,
+    role: PeerRole,
+    expected: Option<&[Identity]>,
+    crl_manager: Option<&crate::tls::crl::CrlManager>,
+) -> Result<(), rustls::Error> {
+    let peer = verify_peer_evidence(
+        end_entity,
+        intermediates,
+        publication.anchors(),
+        now,
+        role,
+    )
+    .map_err(anchor_to_rustls)?;
+    if publication.bundle_fenced(peer.signer_spki()) {
+        return Err(anchor_to_rustls(AnchorError::WithdrawnIssuer {
+            domain: peer.identity().trust_domain().to_string(),
+        }));
+    }
+    if let Some(expected) = expected {
+        if !expected
+            .iter()
+            .any(|identity| identity == peer.identity())
+        {
+            return Err(anchor_to_rustls(AnchorError::UnexpectedPeer {
+                authenticated: peer.identity().to_string(),
+            }));
+        }
+    }
+    let signer = publication.unfenced_signer(peer.signer_spki()).ok_or_else(|| {
+        anchor_to_rustls(AnchorError::WithdrawnIssuer {
+            domain: peer.identity().trust_domain().to_string(),
+        })
+    })?;
+    let mut roots = RootCertStore::empty();
+    roots.add(signer).map_err(|_| {
+        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
+    })?;
+    let usage = match role {
+        PeerRole::Client => KeyUsage::client_auth(),
+        PeerRole::Server => KeyUsage::server_auth(),
+    };
+    let loaded = crl_manager.map(crate::tls::crl::CrlManager::get_crls);
+    let crl_slice = loaded.as_deref().map(Vec::as_slice).unwrap_or(&[]);
+    crate::tls::revocation::verify_cert_chain(
+        end_entity,
+        intermediates,
+        &roots,
+        now,
+        usage,
+        crl_slice,
+    )
+    .map_err(webpki_error_to_rustls)?;
+    Ok(())
+}
+
+fn hint_subjects(publication: &AnchorPublication) -> Vec<DistinguishedName> {
+    let mut roots = RootCertStore::empty();
+    for der in publication.current_signer_ders(SystemTime::now()) {
+        if roots.add(der).is_err() {
+            continue;
+        }
+    }
+    roots.subjects()
+}
+
+/// Outbound verifier. The publication is mandatory. The workload root store is not a fallback.
+#[derive(Debug)]
+pub struct PinnedIdentityVerifier {
+    publication: Arc<AnchorPublication>,
+    expected: Vec<Identity>,
+    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+}
+
+impl PinnedIdentityVerifier {
+    pub fn new(
+        publication: Arc<AnchorPublication>,
+        expected: Vec<Identity>,
+        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> Arc<Self> {
+        Arc::new(Self {
+            publication,
+            expected,
+            crl_manager,
+        })
+    }
+}
+
+impl ServerCertVerifier for PinnedIdentityVerifier {
+    fn verify_server_cert(
+        &self,
+        end_entity: &CertificateDer<'_>,
+        intermediates: &[CertificateDer<'_>],
+        _server_name: &ServerName,
+        ocsp_response: &[u8],
+        now: UnixTime,
+    ) -> Result<ServerCertVerified, rustls::Error> {
+        pinned_chain(
+            &self.publication,
+            end_entity,
+            intermediates,
+            now,
+            PeerRole::Server,
+            Some(self.expected.as_slice()),
+            self.crl_manager.as_deref(),
+        )?;
+        if !ocsp_response.is_empty() {
+            trace!("Unvalidated OCSP response: {ocsp_response:?}");
+        }
+        Ok(ServerCertVerified::assertion())
+    }
+
+    fn verify_tls12_signature(
+        &self,
+        message: &[u8],
+        cert: &CertificateDer<'_>,
+        dss: &DigitallySignedStruct,
+    ) -> Result<HandshakeSignatureValid, rustls::Error> {
+        rustls::crypto::verify_tls12_signature(
+            message,
+            cert,
+            dss,
+            &provider().signature_verification_algorithms,
+        )
+    }
+
+    fn verify_tls13_signature(
+        &self,
+        message: &[u8],
+        cert: &CertificateDer<'_>,
+        dss: &DigitallySignedStruct,
+    ) -> Result<HandshakeSignatureValid, rustls::Error> {
+        rustls::crypto::verify_tls13_signature(
+            message,
+            cert,
+            dss,
+            &provider().signature_verification_algorithms,
+        )
+    }
+
+    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
+        provider()
+            .signature_verification_algorithms
+            .supported_schemes()
+    }
+}
+
+/// Inbound verifier. Every accepted peer must match a current unfenced domain pin.
+#[derive(Debug)]
+pub struct PinnedTrustDomainVerifier {
+    publication: Arc<AnchorPublication>,
+    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+    root_hints: Vec<DistinguishedName>,
+}
+
+impl PinnedTrustDomainVerifier {
+    pub fn new(
+        publication: Arc<AnchorPublication>,
+        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> Arc<Self> {
+        let root_hints = hint_subjects(&publication);
+        Arc::new(Self {
+            publication,
+            crl_manager,
+            root_hints,
+        })
+    }
+}
+
+impl ClientCertVerifier for PinnedTrustDomainVerifier {
+    fn root_hint_subjects(&self) -> &[DistinguishedName] {
+        &self.root_hints
+    }
+
+    fn verify_client_cert(
+        &self,
+        end_entity: &CertificateDer<'_>,
+        intermediates: &[CertificateDer<'_>],
+        now: UnixTime,
+    ) -> Result<ClientCertVerified, rustls::Error> {
+        pinned_chain(
+            &self.publication,
+            end_entity,
+            intermediates,
+            now,
+            PeerRole::Client,
+            None,
+            self.crl_manager.as_deref(),
+        )?;
+        Ok(ClientCertVerified::assertion())
+    }
+
+    fn verify_tls12_signature(
+        &self,
+        message: &[u8],
+        cert: &CertificateDer<'_>,
+        dss: &DigitallySignedStruct,
+    ) -> Result<HandshakeSignatureValid, rustls::Error> {
+        rustls::crypto::verify_tls12_signature(
+            message,
+            cert,
+            dss,
+            &provider().signature_verification_algorithms,
+        )
+    }
+
+    fn verify_tls13_signature(
+        &self,
+        message: &[u8],
+        cert: &CertificateDer<'_>,
+        dss: &DigitallySignedStruct,
+    ) -> Result<HandshakeSignatureValid, rustls::Error> {
+        rustls::crypto::verify_tls13_signature(
+            message,
+            cert,
+            dss,
+            &provider().signature_verification_algorithms,
+        )
+    }
+
+    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
+        provider()
+            .signature_verification_algorithms
+            .supported_schemes()
+    }
+}
diff --git a/src/tls/certificate.rs b/src/tls/certificate.rs
index 1db4fb296b..pinned-verifier 100644
--- a/src/tls/certificate.rs
+++ b/src/tls/certificate.rs
@@ -432,6 +432,66 @@ impl WorkloadCertificate {
         })
     }
 
+    /// Strict inbound constructor. `root_store` is not the peer trust decision.
+    /// Proxy, pool, and SPIRE callers do not use this method.
+    pub fn pinned_server_config(
+        &self,
+        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
+        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> Result<ServerConfig, Error> {
+        let client_cert_verifier =
+            crate::tls::PinnedTrustDomainVerifier::new(publication, crl_manager);
+        let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
+            .with_protocol_versions(tls::tls_versions())
+            .expect("server config must be valid")
+            .with_client_cert_verifier(client_cert_verifier)
+            .with_single_cert(
+                self.cert_and_intermediates_der(),
+                self.private_key.clone_key(),
+            )?;
+        sc.alpn_protocols = vec![b"h2".into()];
+        Ok(sc)
+    }
+
+    /// Strict outbound constructor. `root_store` is not the peer trust decision.
+    /// Proxy, pool, and SPIRE callers do not use this method.
+    pub fn pinned_client_config(
+        &self,
+        identity: Vec<Identity>,
+        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
+        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> Result<ClientConfig, rustls::Error> {
+        let verifier = crate::tls::PinnedIdentityVerifier::new(publication, identity, crl_manager);
+        let mut cc = ClientConfig::builder_with_provider(crate::tls::lib::provider())
+            .with_protocol_versions(tls::tls_versions())
+            .expect("client config must be valid")
+            .dangerous()
+            .with_custom_certificate_verifier(verifier)
+            .with_client_auth_cert(
+                self.cert_and_intermediates_der(),
+                self.private_key.clone_key(),
+            )?;
+        cc.alpn_protocols = vec![b"h2".into()];
+        cc.resumption = Resumption::disabled();
+        cc.enable_sni = false;
+        Ok(cc)
+    }
+
     pub fn dump_chain(&self) -> Bytes {
         self.chain.iter().map(|c| c.as_pem()).join("\n").into()
     }
@@ -801,4 +861,454 @@ mod tests {
         assert!(io_error_is_cert_revoked(&err));
     }
+
+    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
+    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";
+    const URI_C: &str = "spiffe://cmtc-c.mesh.example/ns/orders/sa/api";
+
+    fn ca_params(name: &str) -> rcgen::CertificateParams {
+        use rcgen::{
+            BasicConstraints, CertificateParams, DnType, IsCa, KeyUsagePurpose,
+        };
+        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
+        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
+        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
+        params
+            .distinguished_name
+            .push(DnType::CommonName, name);
+        params
+    }
+
+    fn issuer(name: &str) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
+        rcgen::CertifiedIssuer::self_signed(ca_params(name), rcgen::KeyPair::generate().unwrap())
+            .unwrap()
+    }
+
+    fn issued(
+        name: &str,
+        parent: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
+    ) -> rcgen::CertifiedIssuer<'static, rcgen::KeyPair> {
+        rcgen::CertifiedIssuer::signed_by(ca_params(name), rcgen::KeyPair::generate().unwrap(), parent)
+            .unwrap()
+    }
+
+    fn leaf(
+        uris: &[&str],
+        signer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
+        serial: u64,
+    ) -> (rcgen::KeyPair, rcgen::Certificate) {
+        use rcgen::{
+            CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
+            SerialNumber,
+        };
+        let key = KeyPair::generate().unwrap();
+        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
+        params.is_ca = IsCa::ExplicitNoCa;
+        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
+        params.extended_key_usages = vec![
+            ExtendedKeyUsagePurpose::ClientAuth,
+            ExtendedKeyUsagePurpose::ServerAuth,
+        ];
+        params.serial_number = Some(SerialNumber::from(serial));
+        params.subject_alt_names = uris
+            .iter()
+            .map(|uri| {
+                SanType::URI(rcgen::string::Ia5String::try_from(uri.to_string()).unwrap())
+            })
+            .collect();
+        let cert = params.signed_by(&key, &**signer).unwrap();
+        (key, cert)
+    }
+
+    fn publication_of(
+        root: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
+        pins: Vec<(&str, &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>)>,
+    ) -> Arc<crate::tls::domain_anchors::AnchorPublication> {
+        use crate::tls::domain_anchors::{pin_from_certificate, AnchorPublication, DomainAnchorSet};
+        let set = DomainAnchorSet::try_new(
+            "cmtc-a.mesh.example".into(),
+            root.der().clone(),
+            1,
+            pins.into_iter()
+                .map(|(domain, pin)| pin_from_certificate(domain.into(), pin.der().clone()).unwrap())
+                .collect(),
+        )
+        .unwrap();
+        Arc::new(AnchorPublication::initial(set))
+    }
+
+    fn workload(
+        key: &rcgen::KeyPair,
+        cert: &rcgen::Certificate,
+        unused_root: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>,
+    ) -> WorkloadCertificate {
+        let root_pem = unused_root.pem();
+        WorkloadCertificate::new(
+            key.serialize_pem().as_bytes(),
+            cert.pem().as_bytes(),
+            vec![root_pem.as_bytes()],
+        )
+        .unwrap()
+    }
+
+    fn error_text(err: &std::io::Error) -> String {
+        let mut text = format!("{err} {err:?}");
+        let mut source = std::error::Error::source(err);
+        while let Some(item) = source {
+            text.push_str(&format!(" {item} {item:?}"));
+            source = std::error::Error::source(item);
+        }
+        text
+    }
+
+    fn write_crl(file: &mut NamedTempFile, pem: &str) {
+        use std::io::{Seek, SeekFrom};
+        file.as_file_mut().set_len(0).unwrap();
+        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
+        file.write_all(pem.as_bytes()).unwrap();
+        file.flush().unwrap();
+    }
+
+    fn crl_pem(issuer: &rcgen::CertifiedIssuer<'_, rcgen::KeyPair>, serials: &[u64]) -> String {
+        use rcgen::{
+            CertificateRevocationListParams, KeyIdMethod, RevocationReason, RevokedCertParams,
+            SerialNumber,
+        };
+        let now = time::OffsetDateTime::now_utc();
+        let params = CertificateRevocationListParams {
+            this_update: now,
+            next_update: now + time::Duration::days(30),
+            crl_number: SerialNumber::from(1u64),
+            issuing_distribution_point: None,
+            revoked_certs: serials
+                .iter()
+                .map(|serial| RevokedCertParams {
+                    serial_number: SerialNumber::from(*serial),
+                    revocation_time: now,
+                    reason_code: Some(RevocationReason::KeyCompromise),
+                    invalidity_date: None,
+                })
+                .collect(),
+            key_identifier_method: KeyIdMethod::Sha256,
+        };
+        params.signed_by(issuer).unwrap().pem().unwrap()
+    }
+
+    async fn exchange(
+        server: WorkloadCertificate,
+        client: WorkloadCertificate,
+        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
+        expected_server: Identity,
+        client_crl: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> Result<(Identity, Identity), std::io::Error> {
+        helpers::initialize_telemetry();
+        let server_cfg = server.pinned_server_config(publication.clone(), None).unwrap();
+        let client_cfg = client
+            .pinned_client_config(vec![expected_server], publication, client_crl)
+            .unwrap();
+        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
+        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
+        let addr = listener.local_addr().unwrap();
+        let server_task = tokio::spawn(async move {
+            let (stream, _) = listener.accept().await.unwrap();
+            let mut tls = acceptor.accept(stream).await?;
+            let (_, state) = tls.get_ref();
+            let peer = crate::tls::identity(&crate::tls::certificate_from_connection(state))
+                .ok_or_else(|| std::io::Error::other("missing client identity"))?;
+            tls.write_all(b"serv").await?;
+            Ok::<Identity, std::io::Error>(peer)
+        });
+        let stream = TcpStream::connect(addr).await.unwrap();
+        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
+            .connect(
+                rustls::pki_types::ServerName::IpAddress(
+                    std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
+                ),
+                stream,
+            )
+            .await?;
+        tls.write_all(b"hi").await?;
+        let mut buf = [0u8; 4];
+        tls.read_exact(&mut buf).await?;
+        if &buf != b"serv" {
+            return Err(std::io::Error::other("server payload mismatch"));
+        }
+        let (_, state) = tls.get_ref();
+        let server_identity = crate::tls::identity(&crate::tls::certificate_from_connection(state))
+            .ok_or_else(|| std::io::Error::other("missing server identity"))?;
+        let client_identity = server_task.await.expect("server task")?;
+        Ok((client_identity, server_identity))
+    }
+
+    async fn client_rejection(
+        server: WorkloadCertificate,
+        client: WorkloadCertificate,
+        publication: Arc<crate::tls::domain_anchors::AnchorPublication>,
+        expected_server: Identity,
+        client_crl: Option<Arc<crate::tls::crl::CrlManager>>,
+    ) -> std::io::Error {
+        helpers::initialize_telemetry();
+        let server_cfg = server.pinned_server_config(publication.clone(), None).unwrap();
+        let client_cfg = client
+            .pinned_client_config(vec![expected_server], publication, client_crl)
+            .unwrap();
+        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
+        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
+        let addr = listener.local_addr().unwrap();
+        tokio::spawn(async move {
+            let (stream, _) = listener.accept().await.unwrap();
+            let _ = acceptor.accept(stream).await;
+        });
+        let stream = TcpStream::connect(addr).await.unwrap();
+        tokio::time::timeout(
+            Duration::from_secs(5),
+            tokio_rustls::TlsConnector::from(Arc::new(client_cfg)).connect(
+                rustls::pki_types::ServerName::IpAddress(
+                    std::net::Ipv4Addr::new(0, 0, 0, 0).into(),
+                ),
+                stream,
+            ),
+        )
+        .await
+        .expect("handshake should finish")
+        .expect_err("handshake should fail")
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_accepts_remote_domain() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_B], &b, 22);
+        let (seen_client, seen_server) = exchange(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_B).unwrap(),
+            None,
+        )
+        .await
+        .unwrap();
+        assert_eq!(seen_client, Identity::from_str(URI_A).unwrap());
+        assert_eq!(seen_server, Identity::from_str(URI_B).unwrap());
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_shared_root_wrong_issuer() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_A], &b, 44);
+        let mut roots = rustls::RootCertStore::empty();
+        roots.add(root.der().clone()).unwrap();
+        let intermediate = b.der().clone();
+        crate::tls::revocation::verify_cert_chain(
+            server_cert.der(),
+            &[intermediate],
+            &roots,
+            rustls::pki_types::UnixTime::now(),
+            webpki::KeyUsage::server_auth(),
+            &[],
+        )
+        .expect("shared-root chain is not pin acceptance");
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_A).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(
+            text.contains("foreign domain issuer"),
+            "{text}"
+        );
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_malformed_san() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&["spiffe://cmtc-a.mesh.example/not-an-id"], &a, 45);
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &a),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_A).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(text.contains("unsupported or malformed peer identity"), "{text}");
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_duplicate_san() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_A, URI_B], &a, 46);
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &a),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_A).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(text.contains("exactly one URI SAN"), "{text}");
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_missing_domain() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_C], &a, 47);
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &a),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_C).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(
+            text.contains("untrusted or inactive domain cmtc-c.mesh.example"),
+            "{text}"
+        );
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_expired_pin() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let now = SystemTime::now();
+        let mut expired_params = ca_params("b-expired");
+        expired_params.not_before = (now - Duration::from_secs(7200)).into();
+        expired_params.not_after = (now - Duration::from_secs(60)).into();
+        let expired = rcgen::CertifiedIssuer::signed_by(
+            expired_params,
+            rcgen::KeyPair::generate().unwrap(),
+            &root,
+        )
+        .unwrap();
+        let published = publication_of(
+            &root,
+            vec![
+                ("cmtc-a.mesh.example", &a),
+                ("cmtc-b.mesh.example", &expired),
+            ],
+        );
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_B], &expired, 22);
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &expired),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_B).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(
+            text.contains("untrusted or inactive domain cmtc-b.mesh.example"),
+            "{text}"
+        );
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_rejects_withdrawn_pin() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_B], &b, 22);
+        exchange(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            published.clone(),
+            Identity::from_str(URI_B).unwrap(),
+            None,
+        )
+        .await
+        .unwrap();
+        let spki = published
+            .anchors()
+            .pin_spkis(&"cmtc-b.mesh.example".into())
+            .pop()
+            .unwrap();
+        let withdrawn = published
+            .withdraw_pin(&"cmtc-b.mesh.example".into(), &spki, 2)
+            .unwrap();
+        assert!(withdrawn.bundle_fenced(&spki));
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            Arc::new(withdrawn),
+            Identity::from_str(URI_B).unwrap(),
+            None,
+        )
+        .await;
+        let text = error_text(&err);
+        assert!(
+            text.contains("untrusted or inactive domain cmtc-b.mesh.example"),
+            "{text}"
+        );
+    }
+
+    #[tokio::test]
+    async fn pinned_loopback_crl_rejects_then_recovers() {
+        let root = issuer("root");
+        let a = issued("a", &root);
+        let b = issued("b", &root);
+        let published = publication_of(&root, vec![("cmtc-a.mesh.example", &a), ("cmtc-b.mesh.example", &b)]);
+        let (client_key, client_cert) = leaf(&[URI_A], &a, 11);
+        let (server_key, server_cert) = leaf(&[URI_B], &b, 22);
+        let mut crl_file = NamedTempFile::new().unwrap();
+        write_crl(&mut crl_file, &crl_pem(&b, &[22]));
+        let crl = Arc::new(
+            crate::tls::crl::CrlManager::new(
+                crl_file.path().to_path_buf(),
+                helpers::test_proxy_metrics(),
+            )
+            .unwrap(),
+        );
+        let err = client_rejection(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            published.clone(),
+            Identity::from_str(URI_B).unwrap(),
+            Some(crl.clone()),
+        )
+        .await;
+        assert!(io_error_is_cert_revoked(&err), "{err:?}");
+        write_crl(&mut crl_file, "");
+        crl.load_crl().unwrap();
+        let (seen_client, seen_server) = exchange(
+            workload(&server_key, &server_cert, &b),
+            workload(&client_key, &client_cert, &a),
+            published,
+            Identity::from_str(URI_B).unwrap(),
+            Some(crl),
+        )
+        .await
+        .unwrap();
+        assert_eq!(seen_client, Identity::from_str(URI_A).unwrap());
+        assert_eq!(seen_server, Identity::from_str(URI_B).unwrap());
+    }
 }
```

Apply it in `/private/tmp/cmtc-ztunnel-upstream` only after review. The `index` lines are markers, not a blob to reproduce. These commands have not been run:

```sh
cargo fmt --check -- src/tls/domain_anchors.rs src/tls/workload.rs src/tls/certificate.rs
cargo test --locked --lib pinned_loopback -- --test-threads=1
cargo test --locked --lib -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
```

| Test | Handshake proves | Does not prove |
|---|---|---|
| `pinned_loopback_accepts_remote_domain` | Loopback TLS, domain B server and domain A client, application bytes | ClusterMesh, xDS, or live ztunnel |
| `pinned_loopback_rejects_shared_root_wrong_issuer` | Shared-root `verify_cert_chain` succeeds and the pinned handshake fails | A packet capture |
| `pinned_loopback_rejects_malformed_san` | Unparsable SPIFFE URI rejected during handshake | `certificate::identities` behavior |
| `pinned_loopback_rejects_duplicate_san` | Two URI SANs rejected | Policy AND semantics |
| `pinned_loopback_rejects_missing_domain` | Domain absent from the publication rejected | Remote inventory provenance |
| `pinned_loopback_rejects_expired_pin` | Expired domain pin rejected | Retained-connection expiry |
| `pinned_loopback_rejects_withdrawn_pin` | Same leaf succeeds, then `withdraw_pin` makes the next handshake fail | Pool drain or `retained_tunnel` |
| `pinned_loopback_crl_rejects_then_recovers` | CRL revocation, then an empty reloaded CRL allows a new handshake | An already-open HBONE pool |

CRL checking uses `verify_cert_chain` against the approved direct issuer only, with the existing unknown-status and CRL-expiry policy. The organizational root is not a trust anchor for these constructors. No DaemonSet counter, Cilium metric, or dashboard series is added or renamed.
