# Cursor revised complete implementation proposal

Model: Grok 4.7 Extra High. Still subject to primary source review and local qualification.

The review rejects principal-only policy matching and delayed pin withdrawal. I’ll read the current rule evaluator and then revise the implementation document so issuer checks, policy admission, and expiry stay separate.The principal-only matcher and the “keep the last generation if SPIRE is stale” refresh are withdrawn. Issuer checks stay separate from `Authorization::matches`, and a pin withdrawal takes effect before any bundle fetch. Save the following as a replacement for `docs/research/cursor/CLUSTER_TRUST_IMPLEMENTATION.md`. Nothing here was compiled or applied.

# Cluster-bound trust implementation

Status: revised proposal. Not accepted, not applied, not compiled, and not run. `cmtc-a`/`cmtc-b` still show ClusterMesh reachability only. An imported ztunnel image is not a running workload-mTLS deployment. The ClusterMesh guard in `validateConfig` (`pkg/ztunnel/cell.go`) stays closed.

This revision drops `matches_for_anchors`. TLS pin verification does not decide ports, addresses, namespaces, or denies. `Authorization::matches` is not replaced. A supported-profile screen only accepts or rejects a policy before that existing evaluator runs. Withdrawing a pin updates the publication immediately. A later SPIRE failure, a stale bundle, or an older snapshot cannot put that pin back. Pin expiry drains a retained socket through `apply_retention` without a successful reload. TLS 1.3 evidence does not require a plaintext certificate from the capture.

## Files to copy

| Path | Action |
|---|---|
| `/private/tmp/cmtc-ztunnel-upstream/src/tls/domain_anchors.rs` | New. Complete file below. |
| `/private/tmp/cmtc-ztunnel-upstream/src/tls.rs` | Add `mod domain_anchors;` immediately after `mod certificate;`. No other change. |
| `/private/tmp/cmtc-ztunnel-upstream/src/rbac.rs` | Insert the screen and tests below. `Authorization::matches` is not modified. |

No Cilium file, pool file, or `intent_store_linux.go` change is in this slice. `drive_connection` does not yet call `apply_retention`. That wiring is a deferred gate, not part of this copy.

### `src/tls.rs`

The module list becomes:

```rust
mod certificate;
mod domain_anchors;
mod control;
pub mod crl;
pub mod csr;
mod lib;
#[cfg(any(test, feature = "testing"))]
pub mod mock;
pub mod revocation;
mod workload;
```

### New `src/tls/domain_anchors.rs`

```rust
// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Cluster intermediate pins and retained-connection deadlines.
//!
//! Not called by `TrustDomainVerifier`, `IdentityVerifier`, `SpireClient`,
//! or the HBONE pool. Policy fields are not evaluated here.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webpki::{CertRevocationList, KeyUsage};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::identity::Identity;
use crate::strng::Strng;

use super::certificate;
use super::revocation::verify_cert_chain;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AnchorError {
    #[error("trust domain {0} is empty or has no unexpired pins")]
    UntrustedTrustDomain(String),
    #[error("issuer pin for trust domain {0} is empty, duplicated, or is the organizational root")]
    InvalidPin(String),
    #[error("certificate encoding is not a parseable X.509 certificate")]
    BadEncoding,
    #[error("peer certificate contained {0} SPIFFE URIs; exactly one is required")]
    PeerIdentityCount(usize),
    #[error("peer SPIFFE identity could not be parsed")]
    MalformedIdentity,
    #[error("no single approved pin for trust domain {0} signed this leaf")]
    UnauthorizedIssuer(String),
    #[error("leaf naming trust domain {0} verifies under a pin for another domain")]
    AmbiguousIssuer(String),
    #[error("authenticated peer {authenticated} matched no expected identity")]
    UnexpectedPeer { authenticated: String },
    #[error("bundle for trust domain {domain} contains the organizational root")]
    RejectedRoot { domain: String },
    #[error("bundle for trust domain {domain} contains an authority that is not pinned")]
    UnpinnedAuthority { domain: String },
    #[error("bundle for trust domain {domain} contains no unexpired approved pin")]
    MissingCurrentPin { domain: String },
    #[error("bundle for trust domain {domain} contains withdrawn issuer")]
    WithdrawnIssuer { domain: String },
    #[error("candidate anchor generation {candidate} does not supersede {current}")]
    StaleGeneration { current: u64, candidate: u64 },
    #[error("snapshot generation {candidate} contains withdrawn issuer material")]
    WithdrawnSnapshot { candidate: u64 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    Client,
    Server,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPin {
    pub trust_domain: Strng,
    pub spki_der: Vec<u8>,
    pub der: CertificateDer<'static>,
    pub not_after: SystemTime,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainAnchorSet {
    generation: u64,
    local_domain: Strng,
    organizational_root_spki: Vec<u8>,
    by_domain: HashMap<Strng, Vec<DomainPin>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorPublication {
    set: DomainAnchorSet,
    /// SPIRE responses and old snapshots cannot reintroduce these SPKIs.
    bundle_fenced: HashSet<Vec<u8>>,
    /// A tunnel admitted before this generation for this SPKI stays drained
    /// after an explicit restore. New handshakes use the later generation.
    drain_admitted_before: HashMap<Vec<u8>, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleFetch {
    Authorities(Vec<CertificateDer<'static>>),
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BundleObservation {
    Consistent,
    Unavailable,
    Rejected(AnchorError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedTunnel {
    pub anchor_generation: u64,
    pub peer: Identity,
    pub signer_spki: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedDecision {
    Keep,
    Drain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineSupervisor {
    deadline: SystemTime,
}

impl DomainAnchorSet {
    pub fn try_new(
        local_domain: Strng,
        organizational_root_spki: Vec<u8>,
        generation: u64,
        pins: Vec<DomainPin>,
    ) -> Result<Self, AnchorError> {
        if generation == 0 {
            return Err(AnchorError::StaleGeneration {
                current: 0,
                candidate: generation,
            });
        }
        if local_domain.is_empty() || organizational_root_spki.is_empty() {
            return Err(AnchorError::InvalidPin(local_domain.to_string()));
        }
        let mut by_domain: HashMap<Strng, Vec<DomainPin>> = HashMap::new();
        let mut seen_spki = HashSet::<Vec<u8>>::new();
        for pin in pins {
            if pin.trust_domain.is_empty()
                || pin.spki_der.is_empty()
                || pin.der.is_empty()
                || pin.spki_der == organizational_root_spki
                || !seen_spki.insert(pin.spki_der.clone())
            {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            by_domain.entry(pin.trust_domain.clone()).or_default().push(pin);
        }
        if !by_domain.contains_key(&local_domain) {
            return Err(AnchorError::UntrustedTrustDomain(local_domain.to_string()));
        }
        Ok(Self {
            generation,
            local_domain,
            organizational_root_spki,
            by_domain,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn local_domain(&self) -> &Strng {
        &self.local_domain
    }

    pub fn organizational_root_spki(&self) -> &[u8] {
        &self.organizational_root_spki
    }

    pub fn permits(&self, domain: &Strng) -> bool {
        self.by_domain.contains_key(domain)
    }

    pub fn pin_spkis(&self, domain: &Strng) -> Vec<Vec<u8>> {
        self.by_domain
            .get(domain)
            .map(|pins| pins.iter().map(|pin| pin.spki_der.clone()).collect())
            .unwrap_or_default()
    }

    fn unexpired_pins(&self, domain: &Strng, now: SystemTime) -> Result<&[DomainPin], AnchorError> {
        let pins = self
            .by_domain
            .get(domain)
            .ok_or_else(|| AnchorError::UntrustedTrustDomain(domain.to_string()))?;
        if !pins.iter().any(|pin| pin.not_after > now) {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        Ok(pins.as_slice())
    }
}

impl AnchorPublication {
    pub fn initial(set: DomainAnchorSet) -> Self {
        Self {
            set,
            bundle_fenced: HashSet::new(),
            drain_admitted_before: HashMap::new(),
        }
    }

    pub fn generation(&self) -> u64 {
        self.set.generation
    }

    pub fn anchors(&self) -> &DomainAnchorSet {
        &self.set
    }

    pub fn bundle_fenced(&self, spki: &[u8]) -> bool {
        self.bundle_fenced.contains(spki)
    }

    /// Authoritative profile withdrawal. Applied before any bundle fetch.
    pub fn withdraw_pin(
        &self,
        domain: &Strng,
        spki: &[u8],
        generation: u64,
    ) -> Result<Self, AnchorError> {
        if generation <= self.set.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.set.generation,
                candidate: generation,
            });
        }
        if spki.is_empty() {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        let mut next = self.clone();
        if let Some(pins) = next.set.by_domain.get_mut(domain) {
            pins.retain(|pin| pin.spki_der != spki);
            if pins.is_empty() {
                next.set.by_domain.remove(domain);
            }
        }
        next.bundle_fenced.insert(spki.to_vec());
        next.drain_admitted_before.insert(spki.to_vec(), generation);
        next.set.generation = generation;
        Ok(next)
    }

    /// Explicit corrected profile. Does not read a bundle or an old snapshot.
    pub fn restore_authoritative(
        &self,
        pins: Vec<DomainPin>,
        generation: u64,
    ) -> Result<Self, AnchorError> {
        if generation <= self.set.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.set.generation,
                candidate: generation,
            });
        }
        let Some(first) = pins.first() else {
            return Err(AnchorError::InvalidPin(String::new()));
        };
        let domain = first.trust_domain.clone();
        if domain.is_empty() || self.set.by_domain.contains_key(&domain) {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        let mut next = self.clone();
        let mut seen = HashSet::<Vec<u8>>::new();
        for existing in next.set.by_domain.values().flatten() {
            seen.insert(existing.spki_der.clone());
        }
        for pin in pins {
            if pin.trust_domain != domain
                || pin.spki_der.is_empty()
                || pin.der.is_empty()
                || pin.spki_der == next.set.organizational_root_spki
                || !seen.insert(pin.spki_der.clone())
            {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            next.bundle_fenced.remove(&pin.spki_der);
            next.drain_admitted_before.insert(pin.spki_der.clone(), generation);
            next.set.by_domain.entry(domain.clone()).or_default().push(pin);
        }
        next.set.generation = generation;
        Ok(next)
    }

    pub fn replace(&self, candidate: DomainAnchorSet) -> Result<Self, AnchorError> {
        if candidate.generation <= self.set.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.set.generation,
                candidate: candidate.generation,
            });
        }
        for pins in candidate.by_domain.values() {
            for pin in pins {
                if self.bundle_fenced.contains(&pin.spki_der) {
                    return Err(AnchorError::WithdrawnSnapshot {
                        candidate: candidate.generation,
                    });
                }
            }
        }
        let mut next = self.clone();
        next.set = candidate;
        Ok(next)
    }

    /// Inspect a bundle without changing the publication.
    pub fn observe_bundle(
        &self,
        domain: &Strng,
        fetched: BundleFetch,
        now: SystemTime,
    ) -> BundleObservation {
        let BundleFetch::Authorities(authority_ders) = fetched else {
            return BundleObservation::Unavailable;
        };
        match admit_domain_authorities(&self.set, &self.bundle_fenced, domain, &authority_ders, now)
        {
            Ok(_) => BundleObservation::Consistent,
            Err(error) => BundleObservation::Rejected(error),
        }
    }
}

impl DeadlineSupervisor {
    pub fn at(deadline: SystemTime) -> Self {
        Self { deadline }
    }

    pub fn decision(&self, now: SystemTime) -> RetainedDecision {
        if now >= self.deadline {
            RetainedDecision::Drain
        } else {
            RetainedDecision::Keep
        }
    }
}

pub fn spki_der(der: &[u8]) -> Result<Vec<u8>, AnchorError> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| AnchorError::BadEncoding)?;
    let spki = cert.public_key().raw.to_vec();
    if spki.is_empty() {
        return Err(AnchorError::BadEncoding);
    }
    Ok(spki)
}

pub fn pin_from_certificate(
    trust_domain: Strng,
    der: CertificateDer<'static>,
    not_after: SystemTime,
) -> Result<DomainPin, AnchorError> {
    let spki = spki_der(der.as_ref())?;
    if trust_domain.is_empty() {
        return Err(AnchorError::InvalidPin(trust_domain.to_string()));
    }
    Ok(DomainPin {
        trust_domain,
        spki_der: spki,
        der,
        not_after,
    })
}

fn observed_at(now: UnixTime) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_secs(now.as_secs())
}

fn store_of(pin: &DomainPin) -> Result<RootCertStore, AnchorError> {
    let mut store = RootCertStore::empty();
    let (valid, invalid) = store.add_parsable_certificates(std::iter::once(pin.der.clone()));
    if valid != 1 || invalid != 0 {
        return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
    }
    Ok(store)
}

fn path_accepts(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    pin: &DomainPin,
    now: UnixTime,
    role: PeerRole,
) -> bool {
    let Ok(store) = store_of(pin) else {
        return false;
    };
    let usage = match role {
        PeerRole::Client => KeyUsage::client_auth(),
        PeerRole::Server => KeyUsage::server_auth(),
    };
    let crls: &[CertRevocationList<'static>] = &[];
    verify_cert_chain(end, intermediates, &store, now, usage, crls).is_ok()
}

fn single_identity(end: &CertificateDer<'_>) -> Result<Identity, AnchorError> {
    let (_, parsed) =
        X509Certificate::from_der(end.as_ref()).map_err(|_| AnchorError::BadEncoding)?;
    let ids = certificate::identities(&parsed).map_err(|_| AnchorError::MalformedIdentity)?;
    match ids.as_slice() {
        [id] => Ok(id.clone()),
        other => Err(AnchorError::PeerIdentityCount(other.len())),
    }
}

pub fn verify_peer_certificate(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    let id = single_identity(end)?;
    let domain = id.trust_domain();
    let pins = anchors.unexpired_pins(&domain, observed_at(now))?;
    let mut matched = 0usize;
    for pin in pins {
        if pin.not_after <= observed_at(now) {
            continue;
        }
        if path_accepts(end, intermediates, pin, now, role) {
            matched += 1;
        }
    }
    let mut foreign = false;
    for (other, other_pins) in &anchors.by_domain {
        if other == &domain {
            continue;
        }
        for pin in other_pins {
            if pin.not_after > observed_at(now) && path_accepts(end, intermediates, pin, now, role)
            {
                foreign = true;
            }
        }
    }
    if foreign {
        return Err(AnchorError::AmbiguousIssuer(domain.to_string()));
    }
    if matched != 1 {
        return Err(AnchorError::UnauthorizedIssuer(domain.to_string()));
    }
    Ok(id)
}

pub fn verify_expected_identity(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    expected: &[Identity],
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    let id = verify_peer_certificate(end, intermediates, anchors, now, role)?;
    if expected.iter().any(|want| want == &id) {
        Ok(id)
    } else {
        Err(AnchorError::UnexpectedPeer {
            authenticated: id.to_string(),
        })
    }
}

pub fn admit_domain_authorities(
    anchors: &DomainAnchorSet,
    bundle_fenced: &HashSet<Vec<u8>>,
    domain: &Strng,
    authority_ders: &[CertificateDer<'static>],
    now: SystemTime,
) -> Result<Vec<CertificateDer<'static>>, AnchorError> {
    let pins = anchors.unexpired_pins(domain, now)?;
    if authority_ders.is_empty() {
        return Err(AnchorError::MissingCurrentPin {
            domain: domain.to_string(),
        });
    }
    let mut admitted = Vec::with_capacity(authority_ders.len());
    let mut saw_current = false;
    for der in authority_ders {
        let spki = spki_der(der.as_ref())?;
        if bundle_fenced.contains(&spki) {
            return Err(AnchorError::WithdrawnIssuer {
                domain: domain.to_string(),
            });
        }
        if spki == anchors.organizational_root_spki {
            return Err(AnchorError::RejectedRoot {
                domain: domain.to_string(),
            });
        }
        if !pins.iter().any(|pin| pin.spki_der == spki) {
            return Err(AnchorError::UnpinnedAuthority {
                domain: domain.to_string(),
            });
        }
        if pins
            .iter()
            .any(|pin| pin.not_after > now && pin.spki_der == spki)
        {
            saw_current = true;
        }
        admitted.push(der.clone());
    }
    if !saw_current {
        return Err(AnchorError::MissingCurrentPin {
            domain: domain.to_string(),
        });
    }
    Ok(admitted)
}

pub fn retained_tunnel(
    tunnel: &RetainedTunnel,
    publication: &AnchorPublication,
    now: SystemTime,
) -> RetainedDecision {
    if publication
        .drain_admitted_before
        .get(&tunnel.signer_spki)
        .is_some_and(|generation| tunnel.anchor_generation < *generation)
    {
        return RetainedDecision::Drain;
    }
    let Some(pins) = publication.set.by_domain.get(&tunnel.peer.trust_domain()) else {
        return RetainedDecision::Drain;
    };
    if pins
        .iter()
        .any(|pin| pin.not_after > now && pin.spki_der == tunnel.signer_spki)
    {
        RetainedDecision::Keep
    } else {
        RetainedDecision::Drain
    }
}

pub fn signer_deadline(anchors: &DomainAnchorSet, signer_spki: &[u8]) -> Option<SystemTime> {
    anchors
        .by_domain
        .values()
        .flatten()
        .find(|pin| pin.spki_der == signer_spki)
        .map(|pin| pin.not_after)
}

/// Runtime gate for one retained TCP connection. `Keep` leaves the socket
/// open. `Drain` shuts it down. The HBONE pool does not call this yet.
pub async fn apply_retention(
    stream: &mut TcpStream,
    decision: RetainedDecision,
) -> std::io::Result<RetainedDecision> {
    if decision == RetainedDecision::Drain {
        stream.shutdown().await?;
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::string::Ia5String;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose,
        IsCa, KeyPair, KeyUsagePurpose, SanType,
    };
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const DOMAIN_A: &str = "cmtc-a.mesh.example";
    const DOMAIN_B: &str = "cmtc-b.mesh.example";
    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";
    const URI_A_OTHER: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/other";
    const T0: u64 = 1_700_000_000;

    struct Fixture {
        profile: DomainAnchorSet,
        root_der: CertificateDer<'static>,
        ica_a_der: CertificateDer<'static>,
        ica_b_der: CertificateDer<'static>,
        ica_a_spki: Vec<u8>,
        ica_b_pin: DomainPin,
        leaf_a_by_a: CertificateDer<'static>,
        leaf_a_by_b: CertificateDer<'static>,
        leaf_a_by_root: CertificateDer<'static>,
        leaf_b_by_b: CertificateDer<'static>,
        leaf_two_uris: CertificateDer<'static>,
        leaf_no_uri: CertificateDer<'static>,
        leaf_expired: CertificateDer<'static>,
        now: UnixTime,
    }

    fn ts(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn ut(secs: u64) -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(secs))
    }

    fn ca_params(cn: &str) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, cn);
        params.use_authority_key_identifier_extension = true;
        params
    }

    fn leaf_params(uris: &[&str]) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::ContentCommitment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ClientAuth,
            ExtendedKeyUsagePurpose::ServerAuth,
        ];
        params
            .distinguished_name
            .push(DnType::CommonName, "spiffe-workload");
        for uri in uris {
            let ia5 = Ia5String::try_from((*uri).to_string()).expect("uri");
            params.subject_alt_names.push(SanType::URI(ia5));
        }
        params
    }

    fn owned_der(der: &CertificateDer<'_>) -> CertificateDer<'static> {
        CertificateDer::from(der.as_ref().to_vec())
    }

    fn sign_leaf(uris: &[&str], issuer: &CertifiedIssuer<'_, KeyPair>) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let cert = leaf_params(uris)
            .signed_by(&key, &**issuer)
            .expect("sign leaf");
        owned_der(cert.der())
    }

    fn fixture() -> Fixture {
        let root_key = KeyPair::generate().expect("root key");
        let root = CertifiedIssuer::self_signed(ca_params("organizational-root"), root_key)
            .expect("root cert");
        let ica_a_key = KeyPair::generate().expect("intermediate a key");
        let ica_a =
            CertifiedIssuer::signed_by(ca_params("cluster-a-intermediate"), ica_a_key, &root)
                .expect("intermediate a");
        let ica_b_key = KeyPair::generate().expect("intermediate b key");
        let ica_b =
            CertifiedIssuer::signed_by(ca_params("cluster-b-intermediate"), ica_b_key, &root)
                .expect("intermediate b");
        let root_der = owned_der(root.der());
        let ica_a_der = owned_der(ica_a.der());
        let ica_b_der = owned_der(ica_b.der());
        let pin_deadline = ts(T0 + 100);
        let pin_a =
            pin_from_certificate(DOMAIN_A.into(), ica_a_der.clone(), pin_deadline).expect("pin a");
        let pin_b =
            pin_from_certificate(DOMAIN_B.into(), ica_b_der.clone(), pin_deadline).expect("pin b");
        let root_spki = spki_der(root_der.as_ref()).expect("root spki");
        let profile = DomainAnchorSet::try_new(
            DOMAIN_A.into(),
            root_spki,
            1,
            vec![pin_a.clone(), pin_b.clone()],
        )
        .expect("profile");
        let mut expired_params = leaf_params(&[URI_A]);
        expired_params.not_before = time::OffsetDateTime::from_unix_timestamp(1_600_000_000)
            .expect("expired not_before");
        expired_params.not_after = time::OffsetDateTime::from_unix_timestamp((T0 - 1) as i64)
            .expect("expired not_after");
        let expired_key = KeyPair::generate().expect("expired leaf key");
        let expired = expired_params
            .signed_by(&expired_key, &*ica_a)
            .expect("expired leaf");
        Fixture {
            profile,
            root_der,
            ica_a_der,
            ica_b_der,
            ica_a_spki: pin_a.spki_der,
            ica_b_pin: pin_b,
            leaf_a_by_a: sign_leaf(&[URI_A], &ica_a),
            leaf_a_by_b: sign_leaf(&[URI_A], &ica_b),
            leaf_a_by_root: sign_leaf(&[URI_A], &root),
            leaf_b_by_b: sign_leaf(&[URI_B], &ica_b),
            leaf_two_uris: sign_leaf(&[URI_A, URI_B], &ica_a),
            leaf_no_uri: sign_leaf(&[], &ica_a),
            leaf_expired: owned_der(expired.der()),
            now: ut(T0),
        }
    }

    fn identity_a() -> Identity {
        Identity::from_str(URI_A).expect("identity a")
    }

    fn identity_b() -> Identity {
        Identity::from_str(URI_B).expect("identity b")
    }

    #[test]
    fn same_namespace_and_service_account_in_two_domains_are_different_identities() {
        let a = Identity::from_parts(DOMAIN_A.into(), "orders".into(), "api".into());
        let b = Identity::from_parts(DOMAIN_B.into(), "orders".into(), "api".into());
        assert_ne!(a, b);
        assert!(
            Identity::from_str("spiffe://cmtc-a.mesh.example/cluster/a/ns/orders/sa/api").is_err()
        );
    }

    #[test]
    fn pinned_intermediate_and_exact_san_accept_client_and_server_roles() {
        let fix = fixture();
        let expected = [identity_a()];
        for role in [PeerRole::Server, PeerRole::Client] {
            let got = verify_expected_identity(
                &fix.leaf_a_by_a,
                &[],
                &fix.profile,
                &expected,
                fix.now,
                role,
            )
            .expect("pinned issuer");
            assert_eq!(got, identity_a());
        }
    }

    #[test]
    fn exact_san_rejects_same_domain_different_service_account() {
        let fix = fixture();
        let other = Identity::from_str(URI_A_OTHER).expect("other");
        let err = verify_expected_identity(
            &fix.leaf_a_by_a,
            &[],
            &fix.profile,
            &[other],
            fix.now,
            PeerRole::Server,
        )
        .expect_err("san mismatch");
        assert_eq!(
            err,
            AnchorError::UnexpectedPeer {
                authenticated: URI_A.to_string(),
            }
        );
    }

    #[test]
    fn wrong_domain_signer_is_ambiguous_even_though_root_chain_succeeds() {
        let fix = fixture();
        let mut roots = RootCertStore::empty();
        let (valid, invalid) =
            roots.add_parsable_certificates(std::iter::once(fix.root_der.clone()));
        assert_eq!((valid, invalid), (1, 0));
        verify_cert_chain(
            &fix.leaf_a_by_b,
            &[fix.ica_b_der.clone()],
            &roots,
            fix.now,
            KeyUsage::server_auth(),
            &[],
        )
        .expect("a common-root chain succeeds and is not acceptance");
        let err = verify_peer_certificate(
            &fix.leaf_a_by_b,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("domain A URI signed by domain B pin");
        assert_eq!(err, AnchorError::AmbiguousIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn unknown_signer_and_direct_root_signature_are_unauthorized() {
        let fix = fixture();
        let published = AnchorPublication::initial(fix.profile.clone());
        let only_a = published
            .withdraw_pin(&DOMAIN_B.into(), &fix.ica_b_pin.spki_der, 2)
            .expect("withdraw B");
        let unknown = verify_peer_certificate(
            &fix.leaf_a_by_b,
            &[],
            only_a.anchors(),
            fix.now,
            PeerRole::Server,
        )
        .expect_err("B is not pinned");
        assert_eq!(
            unknown,
            AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string())
        );
        let rooted = verify_peer_certificate(
            &fix.leaf_a_by_root,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Client,
        )
        .expect_err("root is not a pin");
        assert_eq!(rooted, AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn profile_rejects_the_organizational_root_as_a_pin() {
        let fix = fixture();
        let root_pin = pin_from_certificate(
            DOMAIN_A.into(),
            fix.root_der.clone(),
            ts(T0 + 60),
        )
        .expect("root pin material");
        let err = DomainAnchorSet::try_new(
            DOMAIN_A.into(),
            fix.profile.organizational_root_spki().to_vec(),
            1,
            vec![root_pin],
        )
        .expect_err("root cannot be a domain pin");
        assert_eq!(err, AnchorError::InvalidPin(DOMAIN_A.to_string()));
    }

    #[test]
    fn duplicate_pin_in_one_domain_is_not_a_unique_issuer() {
        let fix = fixture();
        let domain: Strng = DOMAIN_A.into();
        let pin = fix
            .profile
            .by_domain
            .get(&domain)
            .expect("pins")
            .first()
            .expect("pin")
            .clone();
        let mut by_domain = HashMap::new();
        by_domain.insert(domain, vec![pin.clone(), pin]);
        let duplicated = DomainAnchorSet {
            generation: 1,
            local_domain: DOMAIN_A.into(),
            organizational_root_spki: fix.profile.organizational_root_spki.clone(),
            by_domain,
        };
        let err = verify_peer_certificate(
            &fix.leaf_a_by_a,
            &[],
            &duplicated,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("two matching pins");
        assert_eq!(err, AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn malformed_and_ambiguous_identities_fail_before_issuer_success() {
        let fix = fixture();
        let none = verify_peer_certificate(
            &fix.leaf_no_uri,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("no uri");
        assert_eq!(none, AnchorError::PeerIdentityCount(0));
        let two = verify_peer_certificate(
            &fix.leaf_two_uris,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("two uris");
        assert_eq!(two, AnchorError::PeerIdentityCount(2));
        let garbage = CertificateDer::from(vec![0x30, 0x00]);
        let err =
            verify_peer_certificate(&garbage, &[], &fix.profile, fix.now, PeerRole::Client)
                .expect_err("truncated der");
        assert_eq!(err, AnchorError::BadEncoding);
    }

    #[test]
    fn expired_leaf_is_unauthorized_without_a_reload() {
        let fix = fixture();
        let err = verify_peer_certificate(
            &fix.leaf_expired,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("expired leaf");
        assert_eq!(err, AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn withdrawal_beats_stale_bundle_partition_and_old_snapshot() {
        let fix = fixture();
        let domain_b: Strng = DOMAIN_B.into();
        let published = AnchorPublication::initial(fix.profile.clone());
        let old_bundle = BundleFetch::Authorities(vec![fix.ica_b_der.clone()]);
        assert_eq!(
            published.observe_bundle(&domain_b, old_bundle.clone(), ts(T0)),
            BundleObservation::Consistent
        );
        let withdrawn = published
            .withdraw_pin(&domain_b, &fix.ica_b_pin.spki_der, 2)
            .expect("withdraw B before refresh");
        assert_eq!(withdrawn.generation(), 2);
        assert!(withdrawn.anchors().pin_spkis(&domain_b).is_empty());
        assert!(withdrawn.bundle_fenced(&fix.ica_b_pin.spki_der));
        let rejected = withdrawn.observe_bundle(&domain_b, old_bundle, ts(T0));
        assert_eq!(
            rejected,
            BundleObservation::Rejected(AnchorError::UntrustedTrustDomain(DOMAIN_B.to_string()))
        );
        let during_partition =
            withdrawn.observe_bundle(&domain_b, BundleFetch::Unavailable, ts(T0));
        assert_eq!(during_partition, BundleObservation::Unavailable);
        assert_eq!(withdrawn.generation(), 2);
        assert!(withdrawn.bundle_fenced(&fix.ica_b_pin.spki_der));
        let snapshot = withdrawn
            .replace(fix.profile.clone())
            .expect_err("generation 1 snapshot");
        assert_eq!(
            snapshot,
            AnchorError::StaleGeneration {
                current: 2,
                candidate: 1,
            }
        );
        let tunnel_b = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_b(),
            signer_spki: fix.ica_b_pin.spki_der.clone(),
        };
        let tunnel_a = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_a(),
            signer_spki: fix.ica_a_spki.clone(),
        };
        assert_eq!(retained_tunnel(&tunnel_b, &withdrawn, ts(T0)), RetainedDecision::Drain);
        assert_eq!(retained_tunnel(&tunnel_a, &withdrawn, ts(T0)), RetainedDecision::Keep);
        let restored = withdrawn
            .restore_authoritative(vec![fix.ica_b_pin.clone()], 3)
            .expect("explicit restore");
        assert!(!restored.bundle_fenced(&fix.ica_b_pin.spki_der));
        assert_eq!(
            restored.observe_bundle(
                &domain_b,
                BundleFetch::Authorities(vec![fix.ica_b_der.clone()]),
                ts(T0),
            ),
            BundleObservation::Consistent
        );
        verify_expected_identity(
            &fix.leaf_b_by_b,
            &[],
            restored.anchors(),
            &[identity_b()],
            ut(T0),
            PeerRole::Server,
        )
        .expect("new handshake after corrected profile");
        assert_eq!(retained_tunnel(&tunnel_b, &restored, ts(T0)), RetainedDecision::Drain);
        let resurrected = AnchorPublication::initial(fix.profile.clone());
        let smuggled = restored
            .replace(resurrected.anchors().clone())
            .expect_err("old snapshot still carries generation 1");
        assert!(matches!(smuggled, AnchorError::StaleGeneration { .. }));
    }

    #[test]
    fn pin_expiry_drains_retained_admission_without_reload() {
        let fix = fixture();
        let published = AnchorPublication::initial(fix.profile.clone());
        let tunnel = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_a(),
            signer_spki: fix.ica_a_spki.clone(),
        };
        assert_eq!(retained_tunnel(&tunnel, &published, ts(T0)), RetainedDecision::Keep);
        let deadline = signer_deadline(published.anchors(), &fix.ica_a_spki).expect("deadline");
        assert_eq!(deadline, ts(T0 + 100));
        assert_eq!(
            retained_tunnel(&tunnel, &published, deadline),
            RetainedDecision::Drain
        );
        let err = verify_peer_certificate(
            &fix.leaf_a_by_a,
            &[],
            published.anchors(),
            ut(T0 + 100),
            PeerRole::Server,
        )
        .expect_err("expired pin closes new handshakes too");
        assert_eq!(err, AnchorError::UntrustedTrustDomain(DOMAIN_A.to_string()));
        assert_eq!(
            published.observe_bundle(
                &DOMAIN_A.into(),
                BundleFetch::Unavailable,
                deadline,
            ),
            BundleObservation::Unavailable
        );
        assert_eq!(published.generation(), 1);
        assert_eq!(retained_tunnel(&tunnel, &published, deadline), RetainedDecision::Drain);
    }

    #[tokio::test]
    async fn deadline_supervisor_shuts_the_retained_socket_only_when_due() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let mut client = TcpStream::connect(address).await.expect("connect");
        let (mut server, _) = listener.accept().await.expect("accept");
        let supervisor = DeadlineSupervisor::at(ts(T0 + 30));
        let keep = supervisor.decision(ts(T0));
        assert_eq!(apply_retention(&mut server, keep).await.expect("keep"), RetainedDecision::Keep);
        client.write_all(b"canary").await.expect("write");
        let mut buf = [0u8; 6];
        server.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"canary");
        let drain = supervisor.decision(ts(T0 + 30));
        assert_eq!(
            apply_retention(&mut server, drain).await.expect("drain"),
            RetainedDecision::Drain
        );
        let mut after = [0u8; 1];
        let n = client.read(&mut after).await.expect("client read");
        assert_eq!(n, 0);
    }
}
```

`CertifiedIssuer::signed_by` in rcgen 0.14.5 takes the signing key by value and the parent as `&Issuer`. `&root` coerces through `Deref`. Leaf signing uses `&**issuer`, matching `CertificateParams::signed_by` in the existing `spireclient.rs` tests. `UnixTime::since_unix_epoch` is the constructor on locked `rustls-pki-types` 1.15.1. `cert.public_key().raw` is the SPKI from `x509-parser` 0.18 via `Deref` to `TbsCertificate`.

The withdrawal test’s first `observe_bundle` after `withdraw_pin` returns `UntrustedTrustDomain`, not `WithdrawnIssuer`, because B’s last pin was removed and `unexpired_pins` fails before the fence check. The fence is still asserted with `bundle_fenced`, and `replace` of generation 1 fails as stale. That order is intentional: the publication no longer offers the domain, and the unavailable fetch does not restore generation 1.

### Insert into `src/rbac.rs` before `#[cfg(test)]`

`Authorization::matches` stays the evaluator. Its field checks are already AND: destination IP, source IP, destination port, service account, principal, and namespace (`matches` lines 119–156). Empty positive lists do not constrain. One rule matches if every clause matches. One clause matches if any `RbacMatch` matches. This screen does not call `matches` and does not rewrite rules.

```rust
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfilePolicyError {
    #[error("pod label constraint cannot be compiled into a service-account grant")]
    PodLabelRequiresDatapath,
    #[error("pinned profile allow uses a service-account match")]
    ServiceAccountGrant,
    #[error("pinned profile allow uses a non-exact principal match")]
    NonExactPrincipal,
    #[error("pinned profile allow has an empty rule or clause")]
    EmptyClause,
    #[error("pinned profile allow has no rules")]
    EmptyAllow,
}

/// Accept or reject a policy before installation. On success the caller
/// evaluates the same `Authorization` with `Authorization::matches`.
pub fn screen_pinned_profile(
    policy: &Authorization,
    pod_labels_constrain_access: bool,
) -> Result<(), ProfilePolicyError> {
    if pod_labels_constrain_access {
        return Err(ProfilePolicyError::PodLabelRequiresDatapath);
    }
    if policy.action != RbacAction::Allow {
        return Ok(());
    }
    if policy.rules.is_empty() {
        return Err(ProfilePolicyError::EmptyAllow);
    }
    for rule in &policy.rules {
        if rule.is_empty() {
            return Err(ProfilePolicyError::EmptyClause);
        }
        for clause in rule {
            if clause.is_empty() {
                return Err(ProfilePolicyError::EmptyClause);
            }
            for mg in clause {
                if !mg.service_accounts.is_empty() || !mg.not_service_accounts.is_empty() {
                    return Err(ProfilePolicyError::ServiceAccountGrant);
                }
                for principal in mg.principals.iter().chain(&mg.not_principals) {
                    if !matches!(principal, StringMatch::Exact(_)) {
                        return Err(ProfilePolicyError::NonExactPrincipal);
                    }
                }
            }
        }
    }
    Ok(())
}
```

### Insert inside `rbac.rs` `mod tests`, before the final closing brace

`StringMatch::matches_principal` strips `spiffe://` and then compares, so exact principals omit that prefix. `ServiceAccountMatch` fields are private; this test module can construct them. The decision helper below only sequences the existing `matches` calls in the same deny-then-allow order as `DemandProxyState::assert_rbac`. It is not installed as a second matcher. `assert_rbac` itself is not changed in this slice.

```rust
    fn profile_conn(port: u16, identity: Identity) -> Connection {
        Connection {
            src_identity: Some(identity),
            src: "10.0.0.1:40000".parse().expect("src"),
            dst: std::net::SocketAddr::from(([10, 0, 0, 2], port)),
            dst_network: "".into(),
        }
    }

    fn orders_api(domain: &str) -> Identity {
        Identity::from_parts(domain.into(), "orders".into(), "api".into())
    }

    fn principal_port(port: u16) -> Authorization {
        allow_policy(
            "principal-port",
            vec![vec![vec![RbacMatch {
                principals: vec![StringMatch::Exact(
                    "cmtc-a.mesh.example/ns/orders/sa/api".into(),
                )],
                destination_ports: vec![port],
                ..RbacMatch::default()
            }]]],
        )
    }

    fn deny_then_allow(denies: &[Authorization], allows: &[Authorization], conn: &Connection) -> bool {
        for policy in denies {
            if policy.matches(conn) {
                return false;
            }
        }
        allows.iter().any(|policy| policy.matches(conn))
    }

    #[test]
    fn pinned_profile_keeps_port_namespace_and_deny_in_the_existing_matcher() {
        let allow = principal_port(80);
        screen_pinned_profile(&allow, false).expect("exact principal and port");
        let peer = orders_api("cmtc-a.mesh.example");
        assert!(allow.matches(&profile_conn(80, peer.clone())));
        assert!(!allow.matches(&profile_conn(31337, peer.clone())));

        let mixed = allow_policy(
            "mixed",
            vec![vec![vec![RbacMatch {
                principals: vec![StringMatch::Exact(
                    "cmtc-a.mesh.example/ns/orders/sa/api".into(),
                )],
                namespaces: vec![StringMatch::Exact("orders".into())],
                destination_ports: vec![80],
                destination_ips: vec![IpNet::new("10.0.0.2".parse().expect("ip"), 32).expect("net")],
                ..RbacMatch::default()
            }]]],
        );
        screen_pinned_profile(&mixed, false).expect("and constraints");
        assert!(mixed.matches(&profile_conn(80, peer.clone())));
        assert!(!mixed.matches(&profile_conn(8080, peer.clone())));
        let other_namespace = Identity::from_parts(
            "cmtc-a.mesh.example".into(),
            "payments".into(),
            "api".into(),
        );
        assert!(!mixed.matches(&profile_conn(80, other_namespace)));

        let deny = Authorization {
            action: RbacAction::Deny,
            name: "deny-80".into(),
            ..allow.clone()
        };
        screen_pinned_profile(&deny, false).expect("deny is not rewritten");
        let on_80 = profile_conn(80, peer);
        assert!(deny.matches(&on_80));
        assert!(allow.matches(&on_80));
        assert!(!deny_then_allow(&[deny], &[allow], &on_80));
    }

    #[test]
    fn label_constraint_and_service_account_grant_are_rejected_before_matching() {
        let allow = principal_port(80);
        let labels = screen_pinned_profile(&allow, true).expect_err("labels");
        assert_eq!(labels, ProfilePolicyError::PodLabelRequiresDatapath);

        let sa_allow = allow_policy(
            "sa",
            vec![vec![vec![RbacMatch {
                service_accounts: vec![ServiceAccountMatch {
                    namespace: "orders".into(),
                    service_account: "api".into(),
                }],
                destination_ports: vec![80],
                ..RbacMatch::default()
            }]]],
        );
        let rejected = screen_pinned_profile(&sa_allow, false).expect_err("sa grant");
        assert_eq!(rejected, ProfilePolicyError::ServiceAccountGrant);
        let domain_a = profile_conn(80, orders_api("cmtc-a.mesh.example"));
        let domain_b = profile_conn(80, orders_api("cmtc-b.mesh.example"));
        assert!(sa_allow.matches(&domain_a));
        assert!(sa_allow.matches(&domain_b));

        let prefix = allow_policy(
            "prefix",
            vec![vec![vec![RbacMatch {
                principals: vec![StringMatch::Prefix("cmtc-a.mesh.example/ns/orders/".into())],
                ..RbacMatch::default()
            }]]],
        );
        assert_eq!(
            screen_pinned_profile(&prefix, false).expect_err("prefix"),
            ProfilePolicyError::NonExactPrincipal
        );
        let empty_clause = allow_policy("empty", vec![vec![]]);
        assert_eq!(
            screen_pinned_profile(&empty_clause, false).expect_err("empty clause"),
            ProfilePolicyError::EmptyClause
        );
    }
```

`RbacMatch` derives `Default`. `allow.clone()` into the deny policy copies the allow rules and then sets `action`. `IpNet` is already imported in `rbac.rs`.

## Commands

From `/private/tmp/cmtc-ztunnel-upstream`, after the three edits. These were not run.

```sh
cargo fmt --check -- src/tls/domain_anchors.rs src/tls.rs src/rbac.rs
RUST_BACKTRACE=1 cargo test --lib domain_anchors --lib rbac -- --test-threads=8
```

No `Cargo.toml` change. Default features remain `tls-aws-lc` and `jemalloc`, which enable the existing `rcgen` 0.14 dependency. Dev-dependencies already include `rcgen` with `pem`, `x509-parser`, and `crypto`, `x509-parser` 0.18 with `verify`, and `time` 0.3. If the 406-test run set `TLS_MODE`, pass that same `FEATURES` value from `Makefile.core.mk`.

Regression after the filtered test:

```sh
RUST_BACKTRACE=1 cargo test --benches --tests --bins
cargo clippy --benches --tests --bins
```

Do not put the organizational root and every intermediate into one `RootCertStore` to turn the wrong-signer test green. That test asserts `verify_cert_chain` to the root succeeds and `verify_peer_certificate` still returns `AmbiguousIssuer`.

## What this slice covers, and the deferred gates

Covered by the tests above, once the primary compiles them:

- Distinct identities for the same namespace and service account in two domains.
- Exact SAN, wrong-domain signer, direct root signature, unpinned signer, two URIs, no URI, truncated DER, expired leaf.
- Authoritative withdrawal before bundle observation. A stale bundle, `BundleFetch::Unavailable`, and a generation-1 snapshot do not restore the pin or the old generation. The withdrawn signer’s retained tunnel is `Drain`. The other signer’s tunnel stays `Keep`. Explicit `restore_authoritative` allows a new handshake and still drains the pre-restore tunnel.
- Pin `not_after` drains retained admission and fails a new handshake with no reload and no generation change.
- `apply_retention` shuts down a real TCP socket at a caller-supplied deadline and leaves it open before that deadline. The deadline is a `SystemTime` value, not a sleep.
- `screen_pinned_profile` rejects pod-label compilation, service-account allows, non-exact principals, and empty allow clauses. Accepted policies are evaluated only by `Authorization::matches`, including port, namespace, destination IP, and deny-before-allow.

Deferred integration gates, not implemented and not passed:

- `TrustDomainVerifier::verify_client_cert`, `IdentityVerifier::verify_server_cert`, `SpireClient::get_bundle`, and `WorkloadHBONEPool` do not call this module. `InboundCertProvider::fetch_cert` still builds peer trust from `self.root_store`. The local-domain `None` skip in `TrustDomainVerifier` remains.
- `drive_connection` does not call `apply_retention` or `retained_tunnel`. The socket test is the gate function on a loopback TCP connection, not an HBONE multiplex.
- `DemandProxyState::assert_rbac` does not call `screen_pinned_profile`. The deny-before-allow test uses the same `matches` order and is not a substitute for the state machine’s missing-policy and xDS-session branches.
- Cilium policy compilation, remote discovery, CNI `PersistRequired`, WireGuard, IPsec, and the eBPF observer are not in this copy.

Smallest wiring slice, still not code here: pass the publication into the two verifiers and `get_bundle`; on `withdraw_pin`, update that publication before the SPIRE call; have each pooled tunnel store `RetainedTunnel` and call `apply_retention` from `drive_connection` when `retained_tunnel` or `DeadlineSupervisor` says `Drain`; call `screen_pinned_profile` before a policy is inserted, then keep using `assert_rbac`. Do not change `validateConfig`.

## TLS 1.3 evidence, when a later lab stage runs

An ordinary TLS 1.3 capture encrypts the handshake certificate. Do not treat a missing cleartext certificate in that capture as a failed identity check, and do not enable session-key logging or copy private keys to produce one. For each flow, bind the encrypted HBONE packet metadata (time, 5-tuple, SNI absent or dummy, sizes) and the absence or presence of the application canary to the proxy authentication and policy log for that same flow, plus a separately exported public leaf, intermediate, issuer name, and SPKI. The canary must not appear when the verifier or the existing matcher denies the flow.

## Unreviewed inputs

`docs/research/cursor/inputs/UNREVIEWED_EBPF_PROPOSAL.md` stays unaccepted. Its Cilium pin predates `06501473`, and that commit is only the membership epoch. The proposal’s C program and `link.BeforeLink` loader were not compiled here. Do not attach it, and do not change the unprivileged Observe DaemonSet.

`cmtc-required-intent-proposal.go.txt` and the adjacent test proposals must not replace `pkg/ztunnel/admission/intent_store_linux.go`. `PersistRequired` is still not on the CNI success path. `List` is intent only.

## Ledger for the rest of `docs/research/cursor/FULL_CODE_REQUEST.md`

These stages are required future gates. A green `domain_anchors` or `rbac` log does not start them and does not open the ClusterMesh guard.

1. **Wire this module.** Call sites named above. Future tests must drive a foreign signer through `server_config` and `outbound_connector`, show `withdraw_pin` draining the matching pooled tunnel while SPIRE is down, and show `screen_pinned_profile` refusing installation before `assert_rbac`. Guard stays closed.
2. **SPIRE registration.** No registration client exists. `pkg/ztunnel/ca/ca_server.go` `CreateCertificate` must not become the protected issuer. Future gate: refuse a trust domain other than the publication’s local domain, and refuse an entry without namespace UID and pod UID. Evidence is the SPIRE entry list and a denied foreign-domain request, without private keys.
3. **Remote discovery.** `IPIdentityPair` has pod UID and service account, not namespace UID or policy generation. `IPIdentityWatcher::OnUpdate` does not copy the service account. Sync callbacks run once; `wsmCommon.Register` overwrites a duplicate prefix. Future gate: authenticated origin, sync epoch, ordered deletes, address and UID reuse, partition expiry, reconnect without resurrecting a deleted UID. Stale ipcache is not authorization.
4. **Cilium policy compilation.** The screen rejects label and service-account allows. The future compiler must keep an explicit Cilium deny, pod-label difference, named port, and application port on the datapath or in the unchanged `matches` input. Unsupported L7, FQDN, and CIDR stay out. Missing, NACKed, and stale policy deny. Plaintext deny is independent of a port allowlist.
5. **Durable admission.** Call the existing `OpenIntentStore` and `PersistRequired` before CNI success. Do not replace the file. Restart uses `List` as intent only, then revalidates the live sandbox and holds the first packet. Corruption, directory-sync poison, API outage, late ACK, and UID reuse fail closed. A readiness log is not this gate.
6. **WireGuard and IPsec, separately.** Both directions, Global Service and direct pod IP, TCP 80, 8080, and 31337. Missing either required layer blocks. Encrypted packet metadata, public chain export, proxy identity, and policy verdict name the same flow. Current encryption-disabled reachability is not this evidence.
7. **Observe-first eBPF, then deny, then Cilium-native.** Separate privileged binary. Reject legacy TC, netkit, and no-TCX. Do not move Cilium’s tail anchor. Counters are pre-verdict packets and bytes. Deny waits until stage 5 is qualified.
8. **Dashboards.** Keep the nine original JSON files and the Operations and Workload Security pages. Planned series stay planned. Attempts, rejections, mTLS TCP connections, HTTP requests, and TLS handshakes stay distinct. Both themes after a real load. No panel is added here.

`validateConfig` remains until stages 1 through 6 have implementation and the evidence above. Stages 7 and 8 do not open it.
