# Cursor cluster-bound trust design

Model: Grok 4.7 Extra High. Proposal only; not compiled, tested or accepted.

The first increment stays a design proposal: per-domain intermediate anchors, with patches written against the verifier and bundle paths already inspected. I’ll check only the new Cilium commit and the watch-registration and pooled-connection sites the proposal has to cite.Save the following as `docs/research/cursor/CLUSTER_TRUST_DESIGN.md`. It is a design proposal only. None of the patches below were applied, built, or tested.

# Cluster-bound workload trust

Status: proposal for review. Not implementation, not lab evidence, and not a Protected claim. The ClusterMesh+ztunnel startup guard stays until the evidence section below has been produced by the primary engineer. This document does not cover the durable-admission subtask.

## Source pins

| Tree | What this proposal uses |
|---|---|
| ztunnel `/private/tmp/cmtc-ztunnel-upstream` | HEAD `8106c026621a6bbf51fbd9190585e6d3549aa527`, read clean earlier in this assignment. Canonical `9a17cb0ff35c20977100de3582c1e4435360f618` was not re-fetched. |
| Cilium `/private/tmp/cilium-ztunnel-authorization-runtime` | HEAD `0650147305f17a1437d5dd76c466180f1d95ea6f`, subject `ztunnel: fence membership acknowledgments across registry restarts`. The only delta from `a23b8479cae4052eff591484e58e3d9b7adc44f8` is `pkg/ztunnel/membership/state.go` and `state_test.go` (12 and 58 lines). That epoch fences in-process ACK counters. It does not bind a certificate issuer to a cluster. |
| Deployed Cilium image | The assignment states the running image is still `a23b8479cae4052eff591484e58e3d9b7adc44f8`. This pass did not inspect the cluster. |
| CMTC | Docs and the absence of a Go SPIRE registration type. No SPIRE or trust-bundle Go API exists in that tree. |

Lab constraints that still apply: persistent `cmtc-a`/`cmtc-b` ClusterMesh, encryption disabled, ztunnel image present on the four nodes and not the active interception path, no sidecars, no root-key distribution, no CMTC-to-proxy production mock, CI deferred. Reachability load is not identity evidence.

## Confirmed interfaces

### Inbound verifier

`WorkloadCertificate::server_config` reads the local leaf and passes only that trust domain into the client-certificate verifier. The webpki store is `self.root_store`, which `new_svid` fills from the selected bundle.

```357:385:/private/tmp/cmtc-ztunnel-upstream/src/tls/certificate.rs
    pub fn server_config(
        &self,
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    ) -> Result<ServerConfig, Error> {
        let td = self.cert.identity().map(|i| match i {
            Identity::Spiffe { trust_domain, .. } => trust_domain,
        });
        // ... WebPkiClientVerifier against self.root_store ...
        let client_cert_verifier =
            crate::tls::workload::TrustDomainVerifier::new(raw_client_cert_verifier, td);
```

`TrustDomainVerifier::verify_client_cert` accepts the chain first, then compares URI text. A missing local identity stores `None`, and `verify_trust_domain` returns success. The local domain is the first URI (`Certificate::identity`). The peer check accepts any one of several URIs.

```65:116:/private/tmp/cmtc-ztunnel-upstream/src/tls/workload.rs
    fn verify_trust_domain(&self, client_cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let Some(want_trust_domain) = &self.trust_domain else {
            return Ok(());
        };
        // ...
        ids.iter()
            .find(|id| match id {
                Identity::Spiffe { trust_domain, .. } => trust_domain == want_trust_domain,
            })
    fn verify_client_cert(...) -> Result<ClientCertVerified, rustls::Error> {
        let res = self.base.verify_client_cert(end_entity, intermediates, now)?;
        self.verify_trust_domain(end_entity)?;
        Ok(res)
    }
```

Each inbound accept rebuilds that config from the current leaf:

```764:771:/private/tmp/cmtc-ztunnel-upstream/src/proxy/inbound.rs
    async fn fetch_cert(&mut self) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        let cert = self.local_workload.fetch_certificate().await?;
        Ok(Arc::new(cert.server_config(self.crl_manager.clone())?))
    }
```

After the handshake, `tls::identity` keeps the first URI only, and RBAC sees that value. The CRL registration then rechecks the peer chain against the **local** leaf store:

```140:216:/private/tmp/cmtc-ztunnel-upstream/src/proxy/inbound.rs
                    let src_identity = {
                        let x509_cert = tls::certificate_from_connection(ssl);
                        tls::identity(&x509_cert)
                    };
                    // ...
        match pi.local_workload_information.fetch_certificate().await {
            Ok(cert) => Some(crl_manager.register(
                crate::tls::revocation::ConnRegistration::from_conn(
                    ssl, peer_identity, cert.root_store(),
                    webpki::KeyUsage::client_auth(), ...
```

### Outbound verifier and pool

`IdentityVerifier::verify_server_cert` runs `verify_cert_chain` against one `RootCertStore`, then requires the full SPIFFE identity to equal one expected value. The expected value includes the domain string from the workload record. The path's trust anchor is not compared with a per-domain pin.

```288:317:/private/tmp/cmtc-ztunnel-upstream/src/tls/workload.rs
    fn verify_server_cert(...) -> Result<ServerCertVerified, rustls::Error> {
        crate::tls::revocation::verify_cert_chain(
            end_entity, intermediates, &self.roots, now,
            KeyUsage::server_auth(), &crls,
        ).map_err(webpki_error_to_rustls)?;
        self.verify_full_san(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }
```

The pooled HBONE tunnel is keyed by source identity, destination identities, and addresses. The key has no certificate generation. Checkout reuses that TLS session. The signer store captured for later CRL checks is `cert.root_store()` from the local leaf at connect time.

```48:58:/private/tmp/cmtc-ztunnel-upstream/src/proxy/h2/client.rs
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    pub dst: SocketAddr,
    pub src: IpAddr,
}
```

```83:116:/private/tmp/cmtc-ztunnel-upstream/src/proxy/pool.rs
        let cert = self.local_workload.fetch_certificate().await?;
        let connector = cert.outbound_connector(key.dst_id.clone(), self.crl_manager.clone())?;
        // ...
            crl_manager.register(crate::tls::revocation::ConnRegistration::from_conn(
                ssl, peer_identity, cert.root_store(),
                webpki::KeyUsage::server_auth(), ...
```

`drive_connection` ends the tunnel when its drain watch changes, when the CRL handle fires, or when the HTTP/2 connection ends. Pin removal does not signal that watch. `PoolState`'s `timeout_tx` is sent only from `Drop`.

`Workload::identity` is `trust_domain` + namespace + service account. `cluster_id` is baggage, not an identity component. `Identity::from_str` accepts only `spiffe://<domain>/ns/<ns>/sa/<sa>`.

`ServiceAccountMatch::matches` ignores `trust_domain`. `Authorization::matches` treats service-account clauses and principal clauses as independent AND terms. Exact principals already exist as `StringMatch::Exact`; prefix, suffix, and presence are also accepted.

### Bundle source

`DelegatedIdentityApi::get_x509_bundles` returns the whole `X509BundleSet`. `SpireClient::get_bundle` keeps one domain. `SecretManager::new_with_spire_client` sets that domain from `cfg.cluster_domain` (`CLUSTER_DOMAIN`, default `cluster.local`). The node identity uses a different variable, `TRUST_DOMAIN`, default `cluster.local`. Cilium copies a third value, `mesh-auth-spiffe-trust-domain`, onto `Workload.trust_domain`.

```326:352:/private/tmp/cmtc-ztunnel-upstream/src/identity/spireclient.rs
    async fn get_bundle(&self) -> Result<Vec<spiffe::cert::Certificate>, Error> {
        let bundle_req = self.client.get_x509_bundles().await...?;
        let td = TrustDomain::new(&self.trust_domain)...?;
        let bundles = match bundle_req.get_bundle(&td) {
            Some(b) => b.authorities(),
            None => return Err(...),
        };
        Ok(bundles.clone())
    }
```

`get_cert_from_spire` rejects an SVID whose SPIFFE ID string differs from the requested identity. It does not check which key signed that URI. `CacheKey::Identity` is already refused for SPIRE fetches; the pod UID is required on the fetch key.

There is no registration client in this tree. Cilium `Server::CreateCertificate` signs the CSR URI after finding a local endpoint with that namespace and service account. It does not compare the URI host with `SpiffeTrustDomain`.

### Native watch and ipcache

`identity.IPIdentityPair` includes `K8sPodUID` and `K8sServiceAccount`. It has no namespace UID, enrollment generation, or policy authority. `IPIdentityWatcher::OnUpdate` copies namespace, pod name, and pod UID into local metadata and does not copy `K8sServiceAccount`. A retained ipcache entry is therefore not a current authorization proof, and it cannot be turned into a SPIFFE issuer pin. Hubble workload names are not an input to either verifier.

Two one-shot mechanisms sit on top of a recurring watch:

- `restartableWatchStore.Watch` runs `onSyncCallbacks` on the first `ListDone`, then sets `onSyncCallbacks = nil` (`pkg/kvstore/store/watchstore.go` lines 161–173). Later reconnects still apply upserts and deletes. Those callbacks do not run again.
- `wsmCommon.Register` stores one function per prefix. A second registration for the same prefix overwrites the first with no error (`pkg/kvstore/store/watchstoremgr.go` lines 48–55). `ready` deletes the function after starting it, so a later sync event for that prefix logs "unregistered" and does not run the function again.

```48:55:/private/tmp/cilium-ztunnel-authorization-runtime/pkg/kvstore/store/watchstoremgr.go
func (mgr *wsmCommon) Register(prefix string, function WSMFunc) {
	if mgr.running.Load() {
		logging.Panic(mgr.log, "Cannot call Register while the watch store manager is running")
	}
	mgr.functions[prefix] = function
}
```

Process-local `membership.Key` has namespace UID and pod UID. The new registry epoch fences ACKs inside one process. Neither value is inside the certificate or the kvstore identity pair.

## Supported profile

Use cluster-specific SPIFFE trust domains and per-domain intermediate anchors. The organizational root stays offline and signs each cluster intermediate. Peer verification never installs that root, and never installs another cluster's intermediate, as a trust anchor.

```text
spiffe://cmtc-a.mesh.example/ns/orders/sa/api
```

The domain is the existing first path label, so `Identity::from_str` stays valid. Dots in `cmtc-a.mesh.example` are part of the trust domain.

A leaf is accepted only when all of the following are true:

1. The leaf has exactly one SPIFFE URI.
2. That URI's domain has at least one unexpired pin in the local allowlist.
3. `verify_cert_chain` succeeds against a `RootCertStore` containing exactly one of those pins, and fails for every other pin in the allowlist.
4. The client also requires the full identity to equal the expected principal. The server authenticates the allowlisted domain; RBAC then requires an exact principal.
5. The organizational root SPKI is not among the pins and not admitted from a bundle.

`pathLen=0` and a URI name constraint on the intermediate are issuance hardening for a later cert-manager change. They are not this verifier. This repository never sets a name constraint. `verify_cert_chain` uses `rustls-webpki` 0.103.16. A path with no name constraint succeeds for whatever anchors are in the store. Chain success plus a matching SAN does not identify the issuer.

### Common-root alternative

Putting the organizational root, or every cluster intermediate, into one `RootCertStore` makes any intermediate that chains to that root a valid signer for every URI. `TrustDomainVerifier` and `IdentityVerifier` then compare strings. An intermediate pinned for cluster B can sign `spiffe://cmtc-a.mesh.example/ns/orders/sa/api` and pass both checks. Name constraints would refuse that leaf only when every certificate on the path carries a URI constraint the library enforces. A constraint-free intermediate issued by the same root is a valid path. webpki returns one path, so the caller of today's `verify_client_cert` cannot tell which issuer was used.

`Workload.cluster_id`, `MeshEgressConfig` string equality, a union of CA certificates, and an extra `/cluster/<id>` path segment do not replace the pin. The parser rejects the extra segment, and an unauthorized issuer can write any path it wants.

### Compromise boundary

- Theft of cluster A's intermediate key allows minting any namespace and service account in A's domain until that pin is removed and pooled tunnels from that generation are drained. B's store does not accept that key.
- Theft of the organizational root allows signing a new intermediate. Verifiers ignore it until a pin for it is admitted. Root theft alone does not impersonate a workload.
- Theft of pin distribution does. Pins come from the profile file in this increment, not from the SPIRE response and not from xDS or ipcache. A later trust-manager feed has to authenticate that file's contents. That feed is not in the CMTC Go tree.
- The SPIFFE ID has no namespace UID or pod UID. Recreating `orders/api` yields the same principal string. Registration must follow the UIDs, and the old SVID must expire or be drained. The current CRL path is not that control: server setup calls `allow_unknown_revocation_status`, and `verify_cert_chain` uses `UnknownStatusPolicy::Allow` and `ExpirationPolicy::Ignore`.

## First increment

One ztunnel change: per-domain pin verification for new handshakes, SPIRE bundle admission against those pins, exact-principal RBAC while a profile is loaded, and retirement of pooled tunnels whose anchor generation changed.

Out of this increment: Cilium guard changes, remote workload authentication, SPIRE `BatchCreateRegistrationEntry`, cert-manager name constraints, ipcache schema changes, and treating the registry epoch as identity. `CATypeInternal` remains a hole until the registration dependency lands; the protected profile simply refuses to treat that signer as an anchor.

Pins in this increment are a local file, the same kind of explicit input as `crl_path`. Tests build that file with `rcgen`. The production fetch still calls `get_x509_bundles`. It does not stub SPIRE.

### Call sites the patch must update

`server_config`, `client_config`, and `outbound_connector` gain `Arc<DomainAnchorSet>`. Production callers:

- `src/proxy/inbound.rs` `InboundCertProvider::fetch_cert` and `Inbound::build_revocation`
- `src/proxy/pool.rs` `ConnSpawner::new_pool_conn`
- `src/proxy/outbound.rs` `proxy_to_double_hbone` (line 305) and the pooled `WorkloadKey` (line 444)

Test callers that must take a fixture anchor set built from their existing CA, not a shared root union:

- `src/tls/certificate.rs` lines 636, 647, 710, 722, 786, 796
- `src/tls/revocation.rs` lines 1049, 1060, 1213, 1224
- `tests/namespaced.rs` lines 1035, 1097, 1179
- `WorkloadKey` literals in `src/proxy/pool.rs` and `src/proxy/h2/client.rs`

`DemandProxyState::new` gains `peer_anchors: None`. `with_peer_anchors` installs the watch. `assert_rbac` is unchanged for a `None` watch, so current RBAC tests keep their meaning.

## Proposed patch, not applied

### `src/tls.rs`

Add `mod domain_anchors;` and `pub use crate::tls::domain_anchors::DomainAnchorSet;`.

### `src/tls/lib.rs`

Add these `TlsError` variants next to `SanTrustDomainError`:

```rust
    #[error("peer certificate must contain exactly one SPIFFE URI, got {0}")]
    PeerIdentityCount(usize),
    #[error("trust domain {0} has no unexpired issuer pin")]
    UntrustedTrustDomain(String),
    #[error("leaf signer is not an approved pin for trust domain {0}")]
    UnauthorizedIssuer(String),
    #[error("leaf for trust domain {0} also verifies under another domain pin")]
    AmbiguousIssuer(String),
    #[error("expected peer identity {0}, authenticated {1}")]
    UnexpectedPeerIdentity(String, String),
```

### `src/tls/domain_anchors.rs` (new file)

```rust
// PROPOSED NEW FILE. Not in the tree. Not compiled.

use crate::identity::Identity;
use crate::strng::Strng;
use crate::tls::revocation::verify_cert_chain;
use crate::tls::{TlsError, certificate};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use webpki::KeyUsage;
use x509_parser::prelude::X509Certificate;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPin {
    pub trust_domain: Strng,
    pub spki_der: Vec<u8>,
    pub der: CertificateDer<'static>,
    pub not_after: SystemTime,
}

#[derive(Clone, Debug)]
pub struct DomainAnchorSet {
    pub generation: u64,
    pub local_domain: Strng,
    /// SPKI DER of the offline organizational root. Never inserted into a store.
    pub organizational_root_spki: Vec<u8>,
    by_domain: HashMap<Strng, Vec<DomainPin>>,
}

impl DomainAnchorSet {
    pub fn load(local_domain: Strng, root_spki: Vec<u8>, pins: Vec<DomainPin>) -> Result<Arc<Self>, TlsError> {
        if local_domain.is_empty() || root_spki.is_empty() {
            return Err(TlsError::UntrustedTrustDomain(local_domain.to_string()));
        }
        let mut by_domain: HashMap<Strng, Vec<DomainPin>> = HashMap::new();
        for pin in pins {
            if pin.spki_der == root_spki {
                return Err(TlsError::UnauthorizedIssuer(pin.trust_domain.to_string()));
            }
            if pin.spki_der.is_empty() || pin.der.is_empty() {
                return Err(TlsError::UnauthorizedIssuer(pin.trust_domain.to_string()));
            }
            by_domain.entry(pin.trust_domain.clone()).or_default().push(pin);
        }
        if !by_domain.contains_key(&local_domain) {
            return Err(TlsError::UntrustedTrustDomain(local_domain.to_string()));
        }
        Ok(Arc::new(Self {
            generation: 1,
            local_domain,
            organizational_root_spki: root_spki,
            by_domain,
        }))
    }

    pub fn permits(&self, domain: &Strng) -> bool {
        self.by_domain.contains_key(domain)
    }

    pub fn unexpired_pins(&self, domain: &Strng, now: SystemTime) -> Result<&[DomainPin], TlsError> {
        let pins = self.by_domain.get(domain).ok_or_else(|| {
            TlsError::UntrustedTrustDomain(domain.to_string())
        })?;
        if !pins.iter().any(|pin| pin.not_after > now) {
            return Err(TlsError::UntrustedTrustDomain(domain.to_string()));
        }
        Ok(pins)
    }

    fn store_of(pin: &DomainPin) -> Result<RootCertStore, TlsError> {
        let mut store = RootCertStore::empty();
        let (_valid, invalid) = store.add_parsable_certificates(std::iter::once(pin.der.clone()));
        if invalid > 0 {
            return Err(TlsError::UnauthorizedIssuer(pin.trust_domain.to_string()));
        }
        Ok(store)
    }
}

fn system_time(now: UnixTime) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(now.as_secs())
}

fn spki_der(der: &CertificateDer<'_>) -> Result<Vec<u8>, rustls::Error> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    })?;
    Ok(cert.public_key().raw.to_vec())
}

fn pin_verifies(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pin: &DomainPin,
    now: UnixTime,
    usage: KeyUsage,
) -> bool {
    let Ok(store) = DomainAnchorSet::store_of(pin) else {
        return false;
    };
    verify_cert_chain(end, intermediates, &store, now, usage, &[]).is_ok()
}

/// Authenticate the leaf against one domain's pins.
/// Exactly one unexpired pin in the whole allowlist may build a path.
pub fn verify_peer_certificate(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    now: UnixTime,
    usage: KeyUsage,
) -> Result<Identity, rustls::Error> {
    let (_, parsed) = X509Certificate::from_der(end).map_err(|_| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
    })?;
    let ids = certificate::identities(&parsed).map_err(|_| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
    })?;
    let [id] = ids.as_slice() else {
        return Err(TlsError::PeerIdentityCount(ids.len()).into());
    };
    let domain = id.trust_domain();
    let pins = anchors.unexpired_pins(&domain, system_time(now))?;
    let mut matched_domain = 0usize;
    for pin in pins {
        if pin.not_after <= system_time(now) {
            continue;
        }
        if pin_verifies(end, intermediates, pin, now, usage) {
            matched_domain += 1;
        }
    }
    if matched_domain != 1 {
        return Err(TlsError::UnauthorizedIssuer(domain.to_string()).into());
    }
    for (other, other_pins) in &anchors.by_domain {
        if other == &domain {
            continue;
        }
        for pin in other_pins {
            if pin.not_after > system_time(now) && pin_verifies(end, intermediates, pin, now, usage) {
                return Err(TlsError::AmbiguousIssuer(domain.to_string()).into());
            }
        }
    }
    let _ = spki_der(end)?;
    Ok(id.clone())
}

pub fn verify_expected_identity(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    expected: &[Identity],
    now: UnixTime,
    usage: KeyUsage,
) -> Result<Identity, rustls::Error> {
    let id = verify_peer_certificate(end, intermediates, anchors, now, usage)?;
    if !expected.iter().any(|want| want == &id) {
        return Err(TlsError::UnexpectedPeerIdentity(
            expected.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(","),
            id.to_string(),
        ).into());
    }
    Ok(id)
}
```

`TlsError` needs `impl From<TlsError> for rustls::Error` using the same `CertificateError::Other(OtherError(Arc::new(...)))` wrapper already used in `verify_trust_domain`. Add that impl in `domain_anchors.rs`.

The `matched_domain != 1` branch covers both "no pin verifies" and "two pins in this domain both verify". The cross-domain loop is the wrong-domain-signer check: a leaf whose URI says A and whose key verifies under B's pin is `AmbiguousIssuer`, even when A's own pin did not verify. Adjust the test names to that split:

- URI domain A, only B's pin verifies: `matched_domain == 0` would return `UnauthorizedIssuer` before the cross-domain loop. Reorder the function so the cross-domain scan runs even when `matched_domain == 0`, and return `AmbiguousIssuer` when another domain's pin verifies. Return `UnauthorizedIssuer` only when every pin fails. The patch implementer must use this order:

```rust
    let mut foreign = false;
    for (other, other_pins) in &anchors.by_domain {
        if other == &domain { continue; }
        for pin in other_pins {
            if pin.not_after > system_time(now) && pin_verifies(end, intermediates, pin, now, usage) {
                foreign = true;
            }
        }
    }
    if foreign {
        return Err(TlsError::AmbiguousIssuer(domain.to_string()).into());
    }
    if matched_domain != 1 {
        return Err(TlsError::UnauthorizedIssuer(domain.to_string()).into());
    }
```

That order is the required one. A leaf signed by B and named as A must not be reported as a generic unknown issuer if B's pin is present.

### Verifier structs

Replace `TrustDomainVerifier`'s wrapped `WebPkiClientVerifier` and `Option<Strng>` with the anchor set. `verify_client_cert` calls `verify_peer_certificate` with `KeyUsage::client_auth()` and does not call a store built from `self.root_store`. Signature methods delegate to `crate::tls::lib::provider()` the way `IdentityVerifier` already does. `root_hint_subjects` returns an empty slice. There is no `None` success path.

Replace `IdentityVerifier.roots` with `anchors: Arc<DomainAnchorSet>`. `verify_server_cert` calls `verify_expected_identity` with `KeyUsage::server_auth()` and the configured expected identities. Delete the separate `verify_full_san` success path so a URI match cannot succeed against a different store.

`WorkloadCertificate::server_config`, `client_config`, and `outbound_connector` take `anchors: Arc<DomainAnchorSet>` and pass it through. They stop building `WebPkiClientVerifier` from `self.root_store`.

`new_svid` stays as it is only after `get_bundle` has already filtered authorities down to admitted pins. The local leaf store is then those pins. Peer verification does not read it.

### SPIRE admission

Add this method on `SpireClient` and call it from `get_cert_from_spire` before `WorkloadCertificate::new_svid`. `get_bundle` becomes a filter over the existing `get_x509_bundles` call.

```rust
// PROPOSED method on SpireClient. Not applied.
async fn admit_local_bundle(
    &self,
    profile: &DomainAnchorSet,
) -> Result<Vec<spiffe::cert::Certificate>, Error> {
    if profile.local_domain.as_str() != self.trust_domain {
        return Err(Error::InvalidTrustDomain(format!(
            "SPIRE client domain {} != profile domain {}",
            self.trust_domain, profile.local_domain
        )));
    }
    let fetched = self.client.get_x509_bundles().await.map_err(|e| {
        Error::FailedToFetchBundle(format!("Failed to fetch X.509 bundles: {e}"))
    })?;
    let td = TrustDomain::new(&self.trust_domain).map_err(|e| {
        Error::InvalidTrustDomain(format!("Invalid trust domain {}: {e}", self.trust_domain))
    })?;
    let bundle = fetched.get_bundle(&td).ok_or_else(|| {
        Error::InvalidTrustDomain(format!("No bundle found for trust domain: {td}"))
    })?;
    let now = SystemTime::now();
    let pins = profile.unexpired_pins(&profile.local_domain, now).map_err(|e| {
        Error::InvalidTrustDomain(e.to_string())
    })?;
    for authority in bundle.authorities() {
        let spki = spki_der_owned(authority.content())?;
        if spki == profile.organizational_root_spki {
            return Err(Error::InvalidTrustDomain(format!(
                "bundle for {td} contains the organizational root"
            )));
        }
        if !pins.iter().any(|pin| pin.spki_der == spki) {
            return Err(Error::InvalidTrustDomain(format!(
                "bundle for {td} contains an unpinned authority"
            )));
        }
    }
    if !pins.iter().any(|pin| {
        bundle.authorities().iter().any(|authority| {
            spki_der_owned(authority.content()).ok().as_ref() == Some(&pin.spki_der)
        })
    }) {
        return Err(Error::InvalidTrustDomain(format!(
            "bundle for {td} is missing its current pin"
        )));
    }
    Ok(bundle.authorities().clone())
}
```

After the SVID stream returns, parse the leaf and call `verify_peer_certificate` against the local domain before `new_svid`. A right URI signed by a foreign key is `UnauthorizedIssuer` or `AmbiguousIssuer` and is not cached.

Startup also fails when `TRUST_DOMAIN`, `CLUSTER_DOMAIN`, and the profile `local_domain` differ. One field, the profile's `local_domain`, is the SPIRE selector. `SecretManager::new_with_spire_client` currently passes `cfg.cluster_domain`; change that argument to the profile domain after the equality check.

Bundle reload is a watch task, independent of `WorkloadCertificate::refresh_at`. On success it publishes `Arc<DomainAnchorSet>` with `generation` incremented and the same pins. On SPIRE or file failure it leaves the previous value in the `watch::Sender`. It does not add a domain that the file omitted. An expired pin is skipped by `unexpired_pins`. A domain whose pins are all expired fails new handshakes.

The watch type is `watch::Sender<Arc<DomainAnchorSet>>`. Hold the sender in the reload task. Clone the receiver into `ProxyInputs`, `ConnSpawner`, and `DemandProxyState`.

### Inbound, outbound, and pooled flows

`InboundCertProvider` clones the anchor receiver. `fetch_cert` uses `receiver.borrow().clone()` as the `server_config` anchor argument, so a new accept sees the current generation without waiting for leaf half-life.

If `tls::identity` returns `None` after accept, close the connection. Do not continue with an empty `src_identity`.

`build_revocation` and `ConnSpawner::new_pool_conn` pass the store of the single pin that verified the peer, not `cert.root_store()`. Add `verified_pin_store(end, intermediates, anchors, now, usage) -> RootCertStore` beside `verify_peer_certificate` and use it in `ConnRegistration::from_conn`. A later CRL recheck then stays inside that pin. CRL unknown-status behavior is unchanged and is not issuer revocation.

`WorkloadKey` gains `pub anchor_generation: u64`. Set it from `anchors.generation` at both construction sites in `src/proxy/outbound.rs`. Pool checkout hashes the generation, so a new request does not reuse a tunnel from the previous generation.

`spawn_connection` gains `mut anchor_generation: watch::Receiver<u64>` (or `Receiver<Arc<DomainAnchorSet>>`). Inside `drive_connection`'s `select`, add:

```rust
        _ = anchor_generation.changed() => {
            debug!("draining HBONE tunnel: issuer pin generation changed");
            teardown.set(Teardown::CertificateRevoked);
        }
```

Use a dedicated watch. Do not send `PoolState.timeout_tx` for this; that channel is also the process-drop drain and is currently fired only from `Drop`. The new branch drops `conn`, which resets multiplexed streams. Idle pooled connections die the same way because their driver uses the same select. Double-HBONE inner tunnels use `outbound_connector` directly and are not in `WorkloadHBONEPool`; their `drain_tx` at `outbound.rs` line 320 must be sent when the anchor generation changes, in the same task that already selects `watch.wait_for_drain()`.

Rotation overlap is two unexpired pins in one domain. A leaf that verifies under exactly one of them is accepted. A leaf that verifies under both is `UnauthorizedIssuer` because `matched_domain != 1`. Publish the overlapping set as one generation. Removing the old pin publishes the next generation and drains tunnels from the previous generation even if their CRL status is unknown.

Partition: a failed `get_x509_bundles` keeps the last published set. New domains are not learned from a partial response. There is no plaintext fallback.

Removal and reconnect: deleting a pin from the profile and reloading publishes a new generation without that pin. A later SPIRE bundle that still contains the removed authority fails `admit_local_bundle` for the local domain, and the previous generation remains until the bundle and the profile agree. A remote domain is not fetched by this increment's `admit_local_bundle`. Remote pins are the file entries for those domains. SPIRE federation transport of remote bundles is a later dependency; until then the file is the only remote pin source, and tests supply it directly.

### Exact principal

Add `peer_anchors: Option<watch::Receiver<Arc<DomainAnchorSet>>>` to `DemandProxyState`, initialized to `None` in `new`, with `with_peer_anchors`.

```rust
// PROPOSED method on Authorization. Not applied.
pub fn matches_for_anchors(&self, conn: &Connection, anchors: &DomainAnchorSet) -> bool {
    let Some(id) = conn.src_identity.as_ref() else {
        return false;
    };
    if !anchors.permits(&id.trust_domain()) {
        return false;
    }
    // Service-account and non-exact principal clauses do not authorize.
    // Deny clauses still use matches(), so an explicit deny keeps its current meaning.
    self.rules.iter().any(|rule| {
        rule.iter().any(|clause| {
            clause.iter().any(|mg| {
                mg.service_accounts.is_empty()
                    && mg.not_service_accounts.is_empty()
                    && mg.principals.iter().any(|p| {
                        matches!(p, StringMatch::Exact(_)) && p.matches_principal(&id.to_strng())
                    })
                    && mg.not_principals.iter().all(|p| !p.matches_principal(&id.to_strng()))
            })
        })
    })
}
```

In `assert_rbac`, when `peer_anchors` is `Some`, evaluate **allow** policies with `matches_for_anchors`. Keep deny policies on `matches`, so a deny of a namespace cannot be skipped. When the watch is `None`, keep today's `matches` for every action. Wire the watch only in the process that loads the profile, at the same place `with_require_inbound_mtls` is applied (`src/state.rs` around the `config.require_inbound_mtls` construction near line 1285).

A policy that says "service account `orders/api`" therefore does not allow cluster B while the profile is loaded. The allow that works is an exact principal `spiffe://cmtc-a.mesh.example/ns/orders/sa/api`.

### Tests that belong to this increment

These are proposed tests. They were not run.

In `src/tls/domain_anchors.rs` under `#[cfg(test)]`, build three `rcgen` CAs: organizational root, intermediate A, intermediate B. The root signs both intermediates. Do not put the root in `DomainAnchorSet` except as `organizational_root_spki`.

| Test | Chain | Expected |
|---|---|---|
| `local_pin_exact_san` | Leaf `spiffe://cmtc-a.mesh.example/ns/orders/sa/api` signed by A | `verify_expected_identity` returns that identity |
| `wrong_domain_signer` | Same URI signed by B; B is pinned only for `cmtc-b.mesh.example` | `AmbiguousIssuer` |
| `unknown_signer` | Same URI signed by a third intermediate absent from the set | `UnauthorizedIssuer` |
| `root_signs_leaf` | Root signs the leaf directly; root is not a pin | `UnauthorizedIssuer` |
| `union_store_would_pass` | One `RootCertStore` containing the root; `verify_cert_chain` of the B-signed leaf succeeds; `verify_peer_certificate` of that same leaf fails | Both assertions |
| `two_uris` | Leaf carries domain A and domain B URIs, signed by A | `PeerIdentityCount` |
| `foreign_domain_not_allowlisted` | Valid B leaf while the set contains only A | `UntrustedTrustDomain` |
| `expired_pin` | A's pin `not_after` is in the past | `UntrustedTrustDomain` |
| `two_pins_one_leaf` | Overlap set; leaf verifies under exactly one | success |
| `two_pins_both_verify` | Same key material installed twice in one domain | `UnauthorizedIssuer` |
| `bundle_contains_root` | `admit_local_bundle` authorities include the root SPKI | `InvalidTrustDomain` |
| `bundle_unpinned_authority` | Bundle authority SPKI is not in the profile | `InvalidTrustDomain` |
| `svid_uri_foreign_signer` | `get_cert_from_spire` path, requested identity matches the URI, signer is B | error, certificate not returned |
| `rbac_same_name` | Profile loaded; identities differ only by trust domain; policy is service-account `orders/api` | `matches_for_anchors` is false |
| `rbac_exact` | Same pair; policy principal is the exact A URI | true for A, false for B |
| `pool_generation` | `WorkloadKey` equality fails when only `anchor_generation` differs | keys differ |

The union-store test is the one that keeps the claim honest: chain validation to the common root succeeds, and the pin verifier still rejects the leaf.

## Design and test dependencies before any guard change

These are not this increment and were not executed.

1. **Registration.** Implement against SPIRE `BatchCreateRegistrationEntry`, not `pkg/ztunnel/ca.Server.CreateCertificate`. Refuse a SPIFFE ID whose trust domain is not the local profile domain. Require namespace UID and pod UID selectors. Delete the old UID's entry before registering a recreated namespace. The SAN can still be identical after that; the verifier cannot see the UID.
2. **Cilium issuer config.** `Validate()` rejects `CATypeInternal` when the protected profile is selected. Do not add pins to `IPIdentityPair`. Do not treat `Workload.cluster_id` or a Hubble name as the issuer. Fixing `wsmCommon.Register` to reject a duplicate prefix, and making sync callbacks cover reconnects, is separate kvstore work. It does not authenticate a peer certificate.
3. **Remote bundles.** Admit another cluster's authorities only when their SPKI equals the profile pin. A SPIRE federation response that adds an authority is a failure, same as `admit_local_bundle`. xDS `trust_domain` remains an unauthenticated string until the remote discovery contract exists.
4. **Authenticated pin distribution.** Replace the local file with a signed trust-manager payload. The signature key is not the organizational root used as a TLS trust anchor.
5. **Stale SVID after pod delete.** Short leaf lifetime plus the generation drain. Do not cite the current CRL unknown-status path as evidence that the old pod is gone.
6. **Lab evidence, required before the guard changes.** On the real two-cluster mesh, with the image IDs that were actually imported:
   - Public leaf and intermediate for each cluster: URI, issuer subject, SPKI DER hash. The verification store does not contain the organizational root. Private keys stay out of the evidence.
   - Packet capture of the HBONE handshake certificate, correlated with the ztunnel identity decision, the exact principal, and the pod UID.
   - Positive: attested `orders/api` on A to an attested workload on B, using application DNS names and ports that are not the trust domain.
   - Negative, at the same capture point: B's same-name identity against a policy naming only A; A's URI signed by B's intermediate; an unknown domain; a bundle that inserts the root; a removed pin whose pooled tunnel is reset; a recreated namespace UID whose old registration is gone.
   - The denial is an authorization or handshake error, not only a timeout.
   - After partition and restore, the legitimate pair succeeds and the negative cases still fail.
   - xDS ACKs, labels, and dashboards are context only.

Unit and mock results, including the table above, do not establish Protected.

## Unknowns

- A live SPIRE `FetchX509Bundles` body was not inspected. Admission rejects the root SPKI if the server includes it.
- Remote xDS records are not an authenticated origin. This increment's foreign-domain successes are fixture results.
- cert-manager `pathLen` and name-constraint settings are outside these checkouts.
- URI name-constraint behavior in `rustls-webpki` 0.103.16 was not used and was not certified.
- The deployed image pin `a23b8479` was not re-checked against the cluster in this pass. The source HEAD `06501473` was read locally and is only the registry epoch.
- `x509-parser` 0.18 is already a dependency. The pin compare uses `public_key().raw`. The `verify` feature is not required because path building performs the signature check. If `SubjectPublicKeyInfo.raw` differs from the bytes SPIRE exposes, compare `subject_public_key` data and record the mismatch; do not fall back to the root.

## Rejected shortcuts

- Treating SAN or trust-domain equality as issuer isolation.
- One trust store that contains the shared root or every intermediate.
- Learning pins from the SPIRE bundle, from xDS, from ipcache, or from `cluster_id`.
- Using the node-local CSR signer for the protected profile.
- Using `ServiceAccountMatch` as the cross-cluster allow.
- Using the current CRL unknown-status path as proof a deleted workload's SVID is dead.
- A CMTC mock in place of SPIRE.
- Removing the ClusterMesh guard after these unit tests.
- Treating the membership execution epoch as cluster binding.

## Order for the primary engineer

1. Review this profile. Keep the architecture record proposed until that review.
2. Add the failing tests in the table, then the new module and the verifier call sites.
3. Filter `get_bundle` and check the SVID signer.
4. Add anchor generation to `WorkloadKey` and the `drive_connection` drain branch.
5. Switch allow-policy evaluation to `matches_for_anchors` only when the watch is installed.
6. Leave registration, pin distribution, and the guard for the dependencies above.

This pass did not apply those changes, did not build images, and did not modify the clusters.
