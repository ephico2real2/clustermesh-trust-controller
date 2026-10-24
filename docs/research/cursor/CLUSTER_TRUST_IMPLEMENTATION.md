# Cursor cluster-bound trust implementation proposal

Model: Grok 4.7 Extra High. Complete-code proposal; primary review and local qualification required.

The first slice has to be a complete, self-contained verifier the primary can copy and test without touching the live handshake or the lab. I’ll check the real certificate, intent-store, and unreviewed proposal interfaces so the code matches those APIs.Save the following as `docs/research/cursor/CLUSTER_TRUST_IMPLEMENTATION.md`. Nothing here was copied into a repository, compiled, or run. The ClusterMesh guard in `pkg/ztunnel/cell.go` stays as it is.

# Cluster-bound trust implementation

Status: copy-ready proposal for the primary engineer. This pass did not edit either fork, did not build, and did not touch the lab. Current `cmtc-a`/`cmtc-b` evidence is ClusterMesh reachability only. A ztunnel image import or version Job is not a running workload-mTLS deployment. None of the mandate gaps below are complete.

The only code to copy in this document is one new ztunnel module and a one-line module declaration. It is an independently testable issuer-pin decision. It is not called by `TrustDomainVerifier`, `IdentityVerifier`, `SpireClient::get_bundle`, or the HBONE pool. Those call sites are the next slice and are not implemented here.

## Source this slice is written against

- ztunnel `/private/tmp/cmtc-ztunnel-upstream`, HEAD `8106c026621a6bbf51fbd9190585e6d3549aa527` when read. New file uses `Identity`, `Strng`, `super::certificate::identities`, and `super::revocation::verify_cert_chain`. `rcgen` 0.14 and `x509-parser` 0.18 APIs used below were checked against those crate versions, not by compiling this file.
- Cilium `/private/tmp/cilium-ztunnel-authorization-runtime`, HEAD `0650147305f17a1437d5dd76c466180f1d95ea6f` (`ztunnel: fence membership acknowledgments across registry restarts` only). The assignment states the deployed image is still `a23b8479cae4052eff591484e58e3d9b7adc44f8`. This pass did not inspect the cluster.
- Guard that this slice must not change: `validateConfig` returns `ztunnel is not compatible with clustermesh` when `EnableZTunnel` is set and `ClusterMesh != nil` (`pkg/ztunnel/cell.go`).
- Live intent store, not to be overwritten: `pkg/ztunnel/admission/intent_store_linux.go`. Public operations read for the ledger: `OpenIntentStore`, `PersistRequired`, `List`, `Close`. It is not on the CNI success path.

## Increment 1 files

| Path | Action |
|---|---|
| `/private/tmp/cmtc-ztunnel-upstream/src/tls/domain_anchors.rs` | New. Complete file below. |
| `/private/tmp/cmtc-ztunnel-upstream/src/tls.rs` | Changed. Insert one module line. No other edit. |

No Go file, no Cilium file, no RBAC edit, no pool edit, and no trust-store union belong in this slice.

### Change `src/tls.rs`

Insert this line directly after `mod certificate;`:

```rust
mod domain_anchors;
```

The resulting module block is:

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

### New file `src/tls/domain_anchors.rs`

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

//! Per-domain intermediate pins for cluster-bound SPIFFE verification.
//!
//! This module is intentionally not referenced by `server_config`,
//! `IdentityVerifier`, or `SpireClient::get_bundle`. A caller must pass the
//! presented leaf and intermediates and a pin set that does not contain the
//! organizational root. Chain success against that root is not a result this
//! module returns.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use webpki::{CertRevocationList, KeyUsage};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

use crate::identity::Identity;
use crate::strng::Strng;

use super::certificate;
use super::revocation::verify_cert_chain;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AnchorError {
    #[error("trust domain {0} is empty or has no pins")]
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
    #[error("candidate anchor generation {candidate} does not supersede {current}")]
    StaleGeneration { current: u64, candidate: u64 },
    #[error("refusing to retire the local trust domain {0}")]
    RetiredLocalDomain(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRole {
    /// Inbound workload peer. Checked with `KeyUsage::client_auth`.
    Client,
    /// Outbound workload peer. Checked with `KeyUsage::server_auth`.
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

    pub fn with_generation(&self, generation: u64) -> Result<Self, AnchorError> {
        if generation <= self.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.generation,
                candidate: generation,
            });
        }
        let mut next = self.clone();
        next.generation = generation;
        Ok(next)
    }

    pub fn retire_domain(&self, domain: &Strng, generation: u64) -> Result<Self, AnchorError> {
        if generation <= self.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.generation,
                candidate: generation,
            });
        }
        if domain == &self.local_domain {
            return Err(AnchorError::RetiredLocalDomain(domain.to_string()));
        }
        if !self.by_domain.contains_key(domain) {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        let mut next = self.clone();
        next.by_domain.remove(domain);
        next.generation = generation;
        Ok(next)
    }

    pub fn restore_domain(&self, pins: Vec<DomainPin>, generation: u64) -> Result<Self, AnchorError> {
        if generation <= self.generation {
            return Err(AnchorError::StaleGeneration {
                current: self.generation,
                candidate: generation,
            });
        }
        let Some(first) = pins.first() else {
            return Err(AnchorError::InvalidPin(String::new()));
        };
        let domain = first.trust_domain.clone();
        if domain.is_empty() {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        if self.by_domain.contains_key(&domain) {
            return Err(AnchorError::InvalidPin(domain.to_string()));
        }
        let mut next = self.clone();
        let mut seen = HashSet::<Vec<u8>>::new();
        for existing in next.by_domain.values().flatten() {
            seen.insert(existing.spki_der.clone());
        }
        for pin in pins {
            if pin.trust_domain != domain
                || pin.spki_der.is_empty()
                || pin.der.is_empty()
                || pin.spki_der == next.organizational_root_spki
                || !seen.insert(pin.spki_der.clone())
            {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            next.by_domain.entry(domain.clone()).or_default().push(pin);
        }
        next.generation = generation;
        Ok(next)
    }

    fn unexpired_pins(&self, domain: &Strng, now: SystemTime) -> Result<&[DomainPin], AnchorError> {
        let pins = self.by_domain.get(domain).ok_or_else(|| {
            AnchorError::UntrustedTrustDomain(domain.to_string())
        })?;
        if !pins.iter().any(|pin| pin.not_after > now) {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        }
        Ok(pins.as_slice())
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
    let (_, parsed) = X509Certificate::from_der(end.as_ref()).map_err(|_| AnchorError::BadEncoding)?;
    let ids = certificate::identities(&parsed).map_err(|_| AnchorError::MalformedIdentity)?;
    match ids.as_slice() {
        [id] => Ok(id.clone()),
        other => Err(AnchorError::PeerIdentityCount(other.len())),
    }
}

/// Accept a leaf only when its one SPIFFE URI names a domain whose unexpired
/// pins contain exactly one path, and no other domain's pin builds a path.
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
            if pin.not_after > observed_at(now) && path_accepts(end, intermediates, pin, now, role) {
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

/// Admit SPIRE bundle authorities only when every authority SPKI is an approved
/// pin for `domain` and at least one unexpired pin is present. The organizational
/// root is rejected even if a bundle includes it.
pub fn admit_domain_authorities(
    anchors: &DomainAnchorSet,
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
        if pins.iter().any(|pin| pin.not_after > now && pin.spki_der == spki) {
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

pub fn select_published(
    current: Option<&DomainAnchorSet>,
    candidate: DomainAnchorSet,
) -> Result<DomainAnchorSet, AnchorError> {
    if let Some(current) = current
        && candidate.generation <= current.generation
    {
        return Err(AnchorError::StaleGeneration {
            current: current.generation,
            candidate: candidate.generation,
        });
    }
    Ok(candidate)
}

pub fn retained_tunnel(
    tunnel: &RetainedTunnel,
    current: &DomainAnchorSet,
    now: SystemTime,
) -> RetainedDecision {
    if tunnel.anchor_generation != current.generation {
        return RetainedDecision::Drain;
    }
    let Some(pins) = current.by_domain.get(&tunnel.peer.trust_domain()) else {
        return RetainedDecision::Drain;
    };
    if pins.iter().any(|pin| pin.not_after > now && pin.spki_der == tunnel.signer_spki) {
        RetainedDecision::Keep
    } else {
        RetainedDecision::Drain
    }
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

    const DOMAIN_A: &str = "cmtc-a.mesh.example";
    const DOMAIN_B: &str = "cmtc-b.mesh.example";
    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";
    const URI_A_OTHER: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/other";

    struct Fixture {
        profile: DomainAnchorSet,
        root_der: CertificateDer<'static>,
        ica_a_der: CertificateDer<'static>,
        ica_b_der: CertificateDer<'static>,
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
        params.distinguished_name.push(DnType::CommonName, "spiffe-workload");
        for uri in uris {
            let ia5 = Ia5String::try_from(uri.to_string()).expect("uri");
            params.subject_alt_names.push(SanType::URI(ia5));
        }
        params
    }

    fn der_of(cert: &impl rcgen::CertificateDerExt) -> CertificateDer<'static> {
        CertificateDer::from(cert.der().as_ref().to_vec())
    }

    fn sign_leaf(uris: &[&str], issuer: &CertifiedIssuer<KeyPair>) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let cert = leaf_params(uris).signed_by(&key, &**issuer).expect("sign leaf");
        der_of(&cert)
    }

    fn fixture() -> Fixture {
        let root_key = KeyPair::generate().expect("root key");
        let root = CertifiedIssuer::self_signed(ca_params("organizational-root"), root_key)
            .expect("root cert");
        let ica_a_key = KeyPair::generate().expect("intermediate a key");
        let ica_a = CertifiedIssuer::signed_by(ca_params("cluster-a-intermediate"), ica_a_key, &root)
            .expect("intermediate a");
        let ica_b_key = KeyPair::generate().expect("intermediate b key");
        let ica_b = CertifiedIssuer::signed_by(ca_params("cluster-b-intermediate"), ica_b_key, &root)
            .expect("intermediate b");
        let root_der = der_of(&root);
        let ica_a_der = der_of(&ica_a);
        let ica_b_der = der_of(&ica_b);
        let not_after = SystemTime::now() + Duration::from_secs(86_400 * 30);
        let pin_a = pin_from_certificate(DOMAIN_A.into(), ica_a_der.clone(), not_after).expect("pin a");
        let pin_b = pin_from_certificate(DOMAIN_B.into(), ica_b_der.clone(), not_after).expect("pin b");
        let root_spki = spki_der(root_der.as_ref()).expect("root spki");
        let profile = DomainAnchorSet::try_new(
            DOMAIN_A.into(),
            root_spki,
            1,
            vec![pin_a, pin_b.clone()],
        )
        .expect("profile");
        let mut expired_params = leaf_params(&[URI_A]);
        expired_params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(3);
        expired_params.not_after = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        let expired_key = KeyPair::generate().expect("expired leaf key");
        let expired = expired_params
            .signed_by(&expired_key, &**&ica_a)
            .expect("expired leaf");
        Fixture {
            profile,
            root_der,
            ica_a_der,
            ica_b_der,
            ica_b_pin: pin_b,
            leaf_a_by_a: sign_leaf(&[URI_A], &ica_a),
            leaf_a_by_b: sign_leaf(&[URI_A], &ica_b),
            leaf_a_by_root: sign_leaf(&[URI_A], &root),
            leaf_b_by_b: sign_leaf(&[URI_B], &ica_b),
            leaf_two_uris: sign_leaf(&[URI_A, URI_B], &ica_a),
            leaf_no_uri: sign_leaf(&[], &ica_a),
            leaf_expired: der_of(&expired),
            now: UnixTime::now(),
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
        assert!(Identity::from_str("spiffe://cmtc-a.mesh.example/cluster/a/ns/orders/sa/api").is_err());
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
        let only_a = fix
            .profile
            .retire_domain(&DOMAIN_B.into(), 2)
            .expect("retire B");
        let unknown = verify_peer_certificate(
            &fix.leaf_a_by_b,
            &[],
            &only_a,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("B is not pinned");
        assert_eq!(unknown, AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string()));
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
    fn profile_rejects_root_as_pin_and_duplicate_spki() {
        let fix = fixture();
        let root_pin = pin_from_certificate(
            DOMAIN_A.into(),
            fix.root_der.clone(),
            SystemTime::now() + Duration::from_secs(60),
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
        let pin = fix.profile.by_domain.get(&domain).expect("pins").[0].clone();
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
        let err = verify_peer_certificate(&garbage, &[], &fix.profile, fix.now, PeerRole::Client)
            .expect_err("truncated der");
        assert_eq!(err, AnchorError::BadEncoding);
    }

    #[test]
    fn unlisted_domain_expired_pin_and_expired_leaf_fail_closed() {
        let fix = fixture();
        let only_a = fix.profile.retire_domain(&DOMAIN_B.into(), 2).expect("retire");
        let foreign = verify_peer_certificate(
            &fix.leaf_b_by_b,
            &[],
            &only_a,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("domain removed");
        assert_eq!(foreign, AnchorError::UntrustedTrustDomain(DOMAIN_B.to_string()));

        let mut expired_pins = fix.profile.clone();
        for pin in expired_pins.by_domain.get_mut(&Strng::from(DOMAIN_A)).expect("a") {
            pin.not_after = UNIX_EPOCH;
        }
        let err = verify_peer_certificate(
            &fix.leaf_a_by_a,
            &[],
            &expired_pins,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("expired pin");
        assert_eq!(err, AnchorError::UntrustedTrustDomain(DOMAIN_A.to_string()));

        let expired_leaf = verify_peer_certificate(
            &fix.leaf_expired,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("expired leaf");
        assert_eq!(expired_leaf, AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn bundle_admission_rejects_root_unpinned_and_empty_and_accepts_current_pin() {
        let fix = fixture();
        let now = SystemTime::now();
        let domain_a: Strng = DOMAIN_A.into();
        let admitted = admit_domain_authorities(
            &fix.profile,
            &domain_a,
            &[fix.ica_a_der.clone()],
            now,
        )
        .expect("current pin");
        assert_eq!(admitted, vec![fix.ica_a_der.clone()]);
        let rooted = admit_domain_authorities(
            &fix.profile,
            &domain_a,
            &[fix.root_der.clone(), fix.ica_a_der.clone()],
            now,
        )
        .expect_err("root in bundle");
        assert_eq!(
            rooted,
            AnchorError::RejectedRoot {
                domain: DOMAIN_A.to_string(),
            }
        );
        let foreign = admit_domain_authorities(
            &fix.profile,
            &domain_a,
            &[fix.ica_b_der.clone()],
            now,
        )
        .expect_err("other domain pin");
        assert_eq!(
            foreign,
            AnchorError::UnpinnedAuthority {
                domain: DOMAIN_A.to_string(),
            }
        );
        let empty = admit_domain_authorities(&fix.profile, &domain_a, &[], now).expect_err("empty");
        assert_eq!(
            empty,
            AnchorError::MissingCurrentPin {
                domain: DOMAIN_A.to_string(),
            }
        );
    }

    #[test]
    fn stale_generation_is_rejected_and_removal_then_restore_drains_old_tunnels() {
        let fix = fixture();
        let now = SystemTime::now();
        let removed = fix.profile.retire_domain(&DOMAIN_B.into(), 2).expect("remove B");
        let stale = select_published(Some(&removed), fix.profile.clone()).expect_err("old generation");
        assert_eq!(
            stale,
            AnchorError::StaleGeneration {
                current: 2,
                candidate: 1,
            }
        );
        let published = select_published(Some(&fix.profile), removed.clone()).expect("publish removal");
        assert_eq!(published.generation(), 2);
        let tunnel = RetainedTunnel {
            anchor_generation: fix.profile.generation(),
            peer: identity_b(),
            signer_spki: fix.ica_b_pin.spki_der.clone(),
        };
        assert_eq!(
            retained_tunnel(&tunnel, &fix.profile, now),
            RetainedDecision::Keep
        );
        assert_eq!(retained_tunnel(&tunnel, &published, now), RetainedDecision::Drain);
        let rotated = fix.profile.with_generation(3).expect("overlap generation");
        assert_eq!(retained_tunnel(&tunnel, &rotated, now), RetainedDecision::Drain);
        verify_peer_certificate(
            &fix.leaf_b_by_b,
            &[],
            &rotated,
            fix.now,
            PeerRole::Server,
        )
        .expect("pin still verifies after generation bump");
        let restored = published
            .restore_domain(vec![fix.ica_b_pin.clone()], 4)
            .expect("restore B");
        let republished = select_published(Some(&published), restored).expect("publish restore");
        verify_expected_identity(
            &fix.leaf_b_by_b,
            &[],
            &republished,
            &[identity_b()],
            fix.now,
            PeerRole::Server,
        )
        .expect("restored pin accepts a new handshake");
        assert_eq!(
            retained_tunnel(&tunnel, &republished, now),
            RetainedDecision::Drain
        );
        let local = republished.retire_domain(&DOMAIN_A.into(), 5).expect_err("local domain");
        assert_eq!(local, AnchorError::RetiredLocalDomain(DOMAIN_A.to_string()));
    }
}
```

## Correction required inside that file before the primary treats it as final

`CertificateDerExt` is not a trait in rcgen 0.14. Replace `der_of` with this function, which uses `Certificate::der` and `CertifiedIssuer::der`, both present in that version:

```rust
fn owned_der(der: &CertificateDer<'_>) -> CertificateDer<'static> {
    CertificateDer::from(der.as_ref().to_vec())
}
```

Then call `owned_der(root.der())`, `owned_der(ica_a.der())`, `owned_der(ica_b.der())`, and `owned_der(cert.der())` / `owned_der(expired.der())` at the four construction sites that currently call `der_of`. Delete the `der_of` function and the `rcgen::CertificateDerExt` bound. `signed_by` returns `rcgen::Certificate`, whose `der()` method returns `&CertificateDer`. `CertifiedIssuer::der` does the same. This is the only helper the file still needs adjusted; do not replace it with a panic stub.

`&**issuer` matches `CertificateParams::signed_by(&self, &impl PublicKeyData, &impl Issuer)`. `CertifiedIssuer` derefs to `Issuer`, so `&**issuer` is `&Issuer`. The existing tree calls the same method as `leaf_params.signed_by(&leaf_key, &*ca_issuer)`.

## Commands and dependencies

Run from `/private/tmp/cmtc-ztunnel-upstream` after copying both edits. These commands have not been run on this file.

```sh
cargo fmt --check -- src/tls/domain_anchors.rs src/tls.rs
RUST_BACKTRACE=1 cargo test --lib domain_anchors -- --test-threads=8
```

Use the same feature set as the existing 406-test run. With no `TLS_MODE`, `Makefile.core.mk` leaves `FEATURES` empty, so Cargo default features apply: `tls-aws-lc` and `jemalloc`. Those enable optional `rcgen`, which the tests import. Dev-dependencies already include `rcgen` 0.14 with `pem`, `x509-parser`, and `crypto`, plus `x509-parser` 0.18 with `verify`, and `time` 0.3. This slice adds no Cargo.toml entries.

After that filtered test is green, the regression command already in the tree is:

```sh
RUST_BACKTRACE=1 cargo test --benches --tests --bins
```

Strict Clippy already wired by the tree:

```sh
cargo clippy --benches --tests --bins
```

Do not add the organizational root, or both intermediates together, to one `RootCertStore` to make a handshake test pass. The test `wrong_domain_signer_is_ambiguous_even_though_root_chain_succeeds` asserts that `verify_cert_chain` to the root succeeds and `verify_peer_certificate` still fails.

## Boundaries of this slice

Implemented, once the primary compiles and runs the tests:

- Distinct SPIFFE identities for the same namespace and service account in two trust domains, using the existing five-segment parser. An extra `/cluster/` segment remains a parse error.
- Positive client and server path checks against one pinned intermediate, with an exact expected identity.
- Rejection of a different service account in the same domain.
- Rejection of domain A's URI signed by domain B's intermediate, including when that leaf chains to the shared root.
- Rejection of an unpinned signer and of a leaf signed directly by the organizational root.
- Rejection of a profile that installs the root SPKI as a pin.
- Rejection of zero URIs, two URIs, and a truncated certificate.
- Rejection of an unlisted domain, an expired pin, and an expired leaf. The expired leaf is reported as `UnauthorizedIssuer` because path building fails and no other domain pin matches. This slice does not surface webpki's expiry type separately.
- Bundle admission that accepts only pinned authorities, requires an unexpired pin, and rejects the root, a foreign pin, and an empty bundle.
- Monotonic generation: a stale candidate is not published; retiring a remote domain, bumping generation, and restoring that domain are distinct operations. A retained tunnel from the old generation is `Drain` even when the pin still verifies a new handshake. The local domain cannot be retired by `retire_domain`.

Not implemented, and not claimed by a green unit run:

- `TrustDomainVerifier::verify_client_cert` still accepts any URI domain equal to the local leaf after `WebPkiClientVerifier` uses `self.root_store`. A `None` local identity still skips the domain check.
- `IdentityVerifier::verify_server_cert` still uses one `RootCertStore` and then compares the SAN.
- `SpireClient::get_bundle` still keeps only `self.trust_domain`, which is `CLUSTER_DOMAIN`, not this pin set.
- `WorkloadKey` has no generation. `WorkloadHBONEPool` can reuse a TLS session. `drive_connection` does not call `retained_tunnel`.
- `ServiceAccountMatch::matches` still ignores `trust_domain`.
- `pkg/ztunnel/cell.go` `validateConfig` is unchanged. Do not remove that error.
- No packet capture, peer identity, or policy verdict was collected.

## Smallest follow-up to wire this module in

That follow-up is not code in this document. After the primary has compiled this module, the next patch should do only the following, still without changing `validateConfig`:

1. `InboundCertProvider::fetch_cert` and `WorkloadCertificate::server_config` stop building peer trust from `self.root_store`. Inbound `verify_client_cert` calls `verify_peer_certificate` with `PeerRole::Client`. Delete the `None` success branch.
2. `IdentityVerifier::verify_server_cert` and both `outbound_connector` call sites (`src/proxy/pool.rs` `new_pool_conn`, `src/proxy/outbound.rs` `proxy_to_double_hbone`) call `verify_expected_identity` with `PeerRole::Server` and the destination identities. The expected identity remains `Workload::identity()`, which includes the trust domain.
3. `SpireClient::get_bundle` passes authorities for the profile's local domain through `admit_domain_authorities` before `WorkloadCertificate::new_svid`. A failed admission does not replace the last published `DomainAnchorSet`. `select_published` decides that replacement.
4. Add `anchor_generation: u64` to `WorkloadKey` at both constructors in `src/proxy/outbound.rs`. On each pooled and double-HBONE connection, build a `RetainedTunnel` from the generation and signer SPKI that verified the handshake. `drive_connection` and the inner double-HBONE drain select drain when `retained_tunnel` returns `Drain`.
5. While a `DomainAnchorSet` is installed, `DemandProxyState::assert_rbac` allow rules match only `StringMatch::Exact` principals that parse as an allowlisted `Identity`. `ServiceAccountMatch` does not grant that allow. Deny rules stay on today's `matches`.

Until those five calls exist, this module cannot fail a live handshake.

## Unreviewed inputs

`docs/research/cursor/inputs/UNREVIEWED_EBPF_PROPOSAL.md` is not accepted. Its Cilium pin is `a23b8479` with a dirty membership tree; that delta is already commit `06501473` and is unrelated to TCX. The C program returns `TCX_NEXT` and counts packets and bytes before a verdict, which is the right quantity if an observer is attached ahead of Cilium, but helper number 1 and `__sync_fetch_and_add` on the per-CPU map have not been accepted by a BPF verifier in this work. `link.BeforeLink` is an API the proposal names and this pass did not compile. Do not copy that loader into CMTC as the observe prototype. The unprivileged `cmtc-node-agent` stays non-root. A later prototype is a separate binary and DaemonSet.

`docs/research/cursor/inputs/cmtc-required-intent-proposal.go.txt` and the adjacent test proposals must not replace `pkg/ztunnel/admission/intent_store_linux.go`. The live file already holds parent and directory descriptors, injects write, sync, and rename, poisons the owner when the directory sync fails after rename, and rejects a conflicting sandbox for the same identity key. Its tests exist under `pkg/ztunnel/admission/intent_store_*_test.go` and were not run here, so they are not qualification. `PersistRequired` is still not called before CNI success. A successful `List` after restart is intent only. The file's own comment says recovery must not admit packets from those records.

## Dependency-ordered ledger

Stages after increment 1 are required future integration gates. They are not unit tests this document implements, and a passing `domain_anchors` run does not start them.

### Stage 1. Wire the pin module

Files: the five call sites in the follow-up section, plus `src/rbac.rs` `Authorization::matches` consumers in `DemandProxyState::assert_rbac`. No change to `pkg/ztunnel/cell.go`.

Future tests, after the wiring exists: the same leaf fixtures through `server_config` and `outbound_connector`, not only through `verify_peer_certificate`. Assert a pooled `WorkloadKey` with the old generation is not checked out, and that `drive_connection` observes `Drain` when generation changes. Assert an allow built from `ServiceAccountMatch { namespace: orders, service_account: api }` does not admit domain B while the profile is loaded, and an exact principal for domain A does.

Command, after compile: `RUST_BACKTRACE=1 cargo test --lib tls::workload --lib identity::spire --lib rbac --lib proxy::pool`.

Evidence before any later security claim: filtered test log showing the foreign-signer handshake error from the real verifier. Not a Protected claim. Guard remains.

### Stage 2. SPIRE registration bound to the local domain

No registration client exists in the ztunnel tree. Cilium `pkg/ztunnel/ca/ca_server.go` `CreateCertificate` signs the CSR URI after a local namespace and service-account lookup and does not compare the URI host with `SpiffeTrustDomain`. Do not use that server as the protected issuer.

Future gate: a SPIRE `BatchCreateRegistrationEntry` caller that refuses a trust domain other than the profile local domain and refuses an entry without namespace UID and pod UID selectors. Delete the old UID before registering a recreated namespace. The SAN string can still repeat; this module will not see the UID.

Evidence: SPIRE entry list for the local domain only, a denied request for the other cluster's domain, and a new pod UID after namespace recreation. Private keys stay out of the logs.

### Stage 3. Authenticated remote workload discovery

Native records are not this authority. `identity.IPIdentityPair` has `K8sPodUID` and `K8sServiceAccount` and has no namespace UID or policy generation. `IPIdentityWatcher::OnUpdate` does not copy the service account into local metadata. `restartableWatchStore` runs `onSyncCallbacks` on the first `ListDone` and then sets them to nil. `wsmCommon.Register` assigns `functions[prefix] = function`, so a second registration for the same prefix overwrites the first. Recurring kvstore events still update keys. A retained ipcache entry is not current authorization.

Future gate, new code, not this slice: an origin-authenticated remote snapshot with a sync epoch, ordered deletes, and rejection of duplicate addresses, missing UID, and stale epochs. Reconnect applies a full snapshot rather than replaying the one-shot callback. Partition keeps the last epoch until its expiry and then fails closed. Recovery requires a newer epoch. Hubble names and `Workload.cluster_id` are not inputs.

Evidence: two clusters with the same namespace, pod name, and service account remain different keys. A deleted UID stays deleted across reconnect. An overwritten watch registration is a test failure, not a successful sync.

### Stage 4. Effective authorization from Cilium policy

`ServiceAccountMatch` ignores trust domain. A service-account principal is coarser than pod labels. Named ports exist on `IPIdentityPair` and on local endpoint status; they are not a complete remote policy compiler.

Future gate: compile the effective Cilium policy for one destination incarnation. Preserve an explicit deny. A second pod with the same service account and a denied label stays denied. Allow TCP 80 does not allow 8080 or 31337. An unsupported L7, FQDN, or CIDR selector stays out of the protected profile. Missing, NACKed, and stale policy deny. Plaintext to the protected destination is denied without depending on a port allowlist.

Evidence: verdict records for those cases on the same pod UID and policy revision. An xDS ACK alone is not the verdict.

### Stage 5. Durable admission

Use the existing `IntentStore` interface. Do not replace `intent_store_linux.go`. `PersistRequired` must return before CNI reports success. `RequiredIntent` has sandbox identity and an incarnation, and the type comment excludes readiness and ACKs. `List` after restart restores intent only. The caller still has to validate the live namespace, pod, and netns, hold the first packet, and collect fresh capture, certificate, and policy evidence. Corruption fails `List` for the whole snapshot (`TestIntentCorruptAndUnsupportedRecordsBlockRecovery` is the existing store test, unrun here). Directory sync failure after rename returns `errRequiredIndeterminate` and poisons the owner. API outage, late ACK, and a changed pod UID or namespace UID do not inherit the old incarnation. Retirement of the old sandbox is required before replacement (`errRequiredConflict`).

A standalone file and a readiness log do not satisfy this stage. The gate is an integration test that fails CNI when `PersistRequired` fails, and that drops traffic after restart until fresh evidence exists. Command, when wired, is the Cilium package test plus a disposable CNI fixture. Not run now.

### Stage 6. Workload mTLS composed with WireGuard and with IPsec

Future lab gate, both directions, Global Service and direct pod IP, TCP 80, 8080, and 31337. Run WireGuard and IPsec as separate required profiles. If either required layer is missing, the flow blocks. Packet capture, authenticated peer identity, and policy verdict must describe the same 5-tuple and pod UID. Reachability and the current image-import Jobs are not this evidence. Encryption is disabled in the current lab, so this stage has not started. The ClusterMesh guard stays through this stage.

### Stage 7. CMTC observe-first eBPF, then deny, then Cilium-native

Do not treat Cilium's BPF build as a CMTC program. After a reviewed loader, a separate privileged binary and DaemonSet may attach an observe-only program ahead of the held Cilium TCX link, return next, and count packets and bytes before Cilium's verdict. Reject legacy TC, netkit, and no-TCX. Do not reorder or replace Cilium's tail anchor. Fence interface reuse with the held link, not only ifindex and name. Do not move the unprivileged Observe DaemonSet into this binary. Deny admission waits until stage 5's CNI and restore behavior is qualified. The permanent gate belongs in Cilium's endpoint loader, not in the prototype.

### Stage 8. Observability

Keep the nine original dashboard JSON files and the two consolidated pages, Operations and Workload Security, described in `DASHBOARD_GUIDE.md` and `docs/handover/CODEX_START_HERE.md`. Add a metric only when the story that owns it is implemented. Planned panels stay planned. Attempts, policy rejections, mTLS TCP connections, HTTP requests, and TLS handshakes are different series. Validate queries against live samples and capture both themes after a real load. This document adds no panel and no screenshot.

## Guard removal

`validateConfig` stays until stages 1 through 6 have been implemented and the primary has the packet, identity, and policy evidence for the positive and negative cases. Increment 1's unit log is not that evidence. Stages 7 and 8 do not by themselves open the guard.The search for the local rcgen sources finished. I’ll check whether it found anything that changes the certificate-signing code in the implementation document.The local search for rcgen 0.14 sources finished without finding a checkout on disk. The signing methods used in the implementation document come from the published rcgen 0.14.5 source instead: `CertifiedIssuer::self_signed` and `CertifiedIssuer::signed_by`.
