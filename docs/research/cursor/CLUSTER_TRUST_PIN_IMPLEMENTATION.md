# Cursor revised complete implementation proposal

Model: Grok 4.7 Extra High. Still subject to primary source review and local qualification.

The pin type still lets a caller supply SPKI and expiry separately from the certificate, and bundle admission can accept a different certificate with the same key. I’ll check the real identity and certificate parsers before replacing that slice.The revised slice is not accepted, copied, or compiled. `DomainPin` no longer takes a caller-supplied SPKI or expiry. Bundle admission returns the configured certificate only when the bytes match, and the peer SAN walk does not use `certificate::identities`. The ClusterMesh guard stays closed.

# Cluster-bound trust implementation

Status: replacement proposal for `docs/research/cursor/CLUSTER_TRUST_IMPLEMENTATION.md`. Source base: ztunnel `8106c026621a6bbf51fbd9190585e6d3549aa527`. Not accepted, not applied, not compiled, and not run. `cmtc-a`/`cmtc-b` remain ClusterMesh reachability only. An imported ztunnel image is not a running workload-mTLS deployment. `validateConfig` in `pkg/ztunnel/cell.go` stays closed.

`Authorization::matches` is unchanged. This module does not evaluate ports, addresses, namespaces, or denies. `screen_pinned_profile` only accepts or rejects a policy before that evaluator runs. Withdrawing a pin updates the publication before any SPIRE read. A failed, stale, or missing bundle cannot put the pin back. Profile freshness and the certificate's own `notAfter` both drain a retained socket without a successful reload. An ordinary TLS 1.3 capture is not treated as a source of certificate plaintext.

## Corrections against the previous proposal

`DomainPin::parse` and `AuthenticatedRoot::parse` are the only constructors. SPKI, encoded `notBefore`, and encoded `notAfter` are read from `X509Certificate::from_der` (`x509-parser` 0.18.1). Leftover bytes are `TrailingBytes`. An anchor must have `BasicConstraints.cA` and `KeyUsage::key_cert_sign()`. A profile deadline later than the encoded `notAfter` is rejected. `try_new`, `restore_domain`, and `replace` parse the certificate again, so a root DER paired with a fabricated SPKI is `InconsistentPin`, and a consistent root certificate is `RejectedRoot`.

`admit_domain_authorities` never returns the bundle's `CertificateDer`. An exact byte match returns `DomainPin::der()`. The same SPKI with a different subject, validity, or name-constraints extension is `SubstitutedSubject`, `SubstitutedExpiry`, or `SubstitutedConstraints`. Pins stay the authenticated configuration.

`supported_identity` reads every `GeneralName` from `subject_alternative_name()`. That helper uses `get_extension_unique`, so a duplicate SAN extension is an error. A URI that `Identity::from_str` rejects, including an empty namespace, fails the certificate even when another URI is a valid SPIFFE ID. DNS and other non-URI names are `UnsupportedSan`. Two valid SPIFFE URIs are `AmbiguousSan`. `certificate::identities` still drops unparsable URIs; the tests call it only to show that difference.

`rustls-webpki` 0.103.16 `anchor_from_trusted_cert` does not check the trust anchor's CA bit, and `check_signed_chain` sets `issuer_key_usage` to `None` for the anchor. `check_validity` applies to path certificates, not to that anchor. The tests keep a `verify_cert_chain` success beside `AuthorityExpired` and `ProfileStale`.

## Files to copy

| Path | Action |
|---|---|
| `/private/tmp/cmtc-ztunnel-upstream/src/tls/domain_anchors.rs` | New file. Complete contents below. |
| `/private/tmp/cmtc-ztunnel-upstream/src/tls.rs` | Insert one line, `mod domain_anchors;`, immediately after `mod certificate;`. |
| `/private/tmp/cmtc-ztunnel-upstream/src/rbac.rs` | Insert the screen before `#[cfg(test)]` and the tests before the closing brace of `mod tests`. `Authorization::matches` is not edited. |

No pool, verifier, SPIRE, Cilium, or `intent_store_linux.go` edit is in this slice. `drive_connection` does not call `apply_retention`. That wiring is a deferred gate.

### `/private/tmp/cmtc-ztunnel-upstream/src/tls.rs`

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

### `/private/tmp/cmtc-ztunnel-upstream/src/tls/domain_anchors.rs`

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

//! Per-domain intermediate pins and retained-connection deadlines.
//!
//! Not called by `TrustDomainVerifier`, `IdentityVerifier`, `SpireClient`,
//! or the HBONE pool. Policy fields are not evaluated here.
//! `certificate::identities` is not used: it drops SAN values it cannot parse.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use webpki::{CertRevocationList, KeyUsage};
use x509_parser::asn1_rs::FromDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;

use crate::identity::Identity;
use crate::strng::Strng;

use super::revocation::verify_cert_chain;

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum AnchorError {
    #[error("trust domain {0} is empty or has no pins")]
    UntrustedTrustDomain(String),
    #[error("trust domain {0} has an empty or duplicated pin")]
    InvalidPin(String),
    #[error("pin fields do not match the parsed certificate")]
    InconsistentPin,
    #[error("certificate has trailing DER bytes")]
    TrailingBytes,
    #[error("certificate encoding is not a parseable X.509 certificate")]
    BadEncoding,
    #[error("anchor is not a CA certificate")]
    NotCertificateAuthority,
    #[error("anchor key usage does not allow certificate signing")]
    InvalidKeyUsage,
    #[error("peer certificate is a CA rather than a workload leaf")]
    NotALeaf,
    #[error("profile deadline {profile_not_after:?} is after encoded expiry {encoded_not_after:?}")]
    ProfileExtendsAuthority {
        encoded_not_after: SystemTime,
        profile_not_after: SystemTime,
    },
    #[error("profile deadline {profile_not_after:?} is not inside encoded validity starting {encoded_not_before:?}")]
    ProfileOutsideAuthority {
        encoded_not_before: SystemTime,
        profile_not_after: SystemTime,
    },
    #[error("trust domain {domain} is inside its encoded validity but past its profile deadline")]
    ProfileStale { domain: String },
    #[error("trust domain {domain} is outside the anchor certificate validity")]
    AuthorityExpired { domain: String },
    #[error("organizational root cannot be a domain pin for {domain}")]
    RejectedRoot { domain: String },
    #[error("SAN extension is missing, empty, duplicated, or contains a non-profile URI")]
    MalformedSan,
    #[error("SAN extension contains a name outside the supported SPIFFE URI profile")]
    UnsupportedSan,
    #[error("SAN extension contains more than one supported SPIFFE URI")]
    AmbiguousSan,
    #[error("no single approved pin for trust domain {0} signed this leaf")]
    UnauthorizedIssuer(String),
    #[error("leaf naming trust domain {0} verifies under a pin for another domain")]
    AmbiguousIssuer(String),
    #[error("authenticated peer {authenticated} matched no expected identity")]
    UnexpectedPeer { authenticated: String },
    #[error("bundle certificate for {domain} changes the approved subject")]
    SubstitutedSubject { domain: String },
    #[error("bundle certificate for {domain} changes the approved validity")]
    SubstitutedExpiry { domain: String },
    #[error("bundle certificate for {domain} changes the approved name constraints")]
    SubstitutedConstraints { domain: String },
    #[error("bundle certificate for {domain} differs from the approved certificate")]
    SubstitutedCertificate { domain: String },
    #[error("bundle for trust domain {domain} contains an authority that is not pinned")]
    UnpinnedAuthority { domain: String },
    #[error("bundle for trust domain {domain} contains no current approved pin")]
    MissingCurrentPin { domain: String },
    #[error("bundle for trust domain {domain} contains a withdrawn issuer")]
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
pub struct AuthenticatedRoot {
    der: CertificateDer<'static>,
    spki_der: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainPin {
    trust_domain: Strng,
    der: CertificateDer<'static>,
    spki_der: Vec<u8>,
    encoded_not_before: SystemTime,
    encoded_not_after: SystemTime,
    profile_not_after: SystemTime,
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
    bundle_fenced: HashSet<Vec<u8>>,
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

impl AuthenticatedRoot {
    pub fn parse(der: CertificateDer<'static>) -> Result<Self, AnchorError> {
        let cert = strict_cert(der.as_ref())?;
        require_signing_ca(&cert)?;
        Ok(Self {
            spki_der: cert.public_key().raw.to_vec(),
            der,
        })
    }

    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki_der
    }
}

impl DomainPin {
    /// `profile_not_after` is a deployment freshness limit. It cannot be later
    /// than the authority certificate's encoded `notAfter`.
    pub fn parse(
        trust_domain: Strng,
        der: CertificateDer<'static>,
        profile_not_after: SystemTime,
    ) -> Result<Self, AnchorError> {
        if trust_domain.is_empty() {
            return Err(AnchorError::InvalidPin(trust_domain.to_string()));
        }
        let cert = strict_cert(der.as_ref())?;
        require_signing_ca(&cert)?;
        let (encoded_not_before, encoded_not_after) = encoded_bounds(&cert)?;
        check_profile_window(encoded_not_before, encoded_not_after, profile_not_after)?;
        Ok(Self {
            trust_domain,
            spki_der: cert.public_key().raw.to_vec(),
            der,
            encoded_not_before,
            encoded_not_after,
            profile_not_after,
        })
    }

    pub fn trust_domain(&self) -> &Strng {
        &self.trust_domain
    }

    pub fn der(&self) -> &CertificateDer<'static> {
        &self.der
    }

    pub fn spki(&self) -> &[u8] {
        &self.spki_der
    }

    pub fn encoded_not_before(&self) -> SystemTime {
        self.encoded_not_before
    }

    pub fn encoded_not_after(&self) -> SystemTime {
        self.encoded_not_after
    }

    pub fn profile_not_after(&self) -> SystemTime {
        self.profile_not_after
    }
}

impl DomainAnchorSet {
    pub fn try_new(
        local_domain: Strng,
        root: &AuthenticatedRoot,
        generation: u64,
        pins: Vec<DomainPin>,
    ) -> Result<Self, AnchorError> {
        if generation == 0 || local_domain.is_empty() {
            return Err(AnchorError::InvalidPin(local_domain.to_string()));
        }
        let root_spki = verified_root_spki(root)?;
        let mut by_domain: HashMap<Strng, Vec<DomainPin>> = HashMap::new();
        let mut seen_spki = HashSet::<Vec<u8>>::new();
        for pin in pins {
            require_consistent(&pin, &root_spki)?;
            if !seen_spki.insert(pin.spki_der.clone()) {
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
            organizational_root_spki: root_spki,
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

    pub fn canonical_ders(&self, domain: &Strng) -> Vec<CertificateDer<'static>> {
        self.by_domain
            .get(domain)
            .map(|pins| pins.iter().map(|pin| pin.der.clone()).collect())
            .unwrap_or_default()
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

    /// Authoritative withdrawal. The publication changes before any bundle fetch.
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
            pins.retain(|pin| pin.spki_der.as_slice() != spki);
            if pins.is_empty() {
                next.set.by_domain.remove(domain);
            }
        }
        next.bundle_fenced.insert(spki.to_vec());
        next.drain_admitted_before.insert(spki.to_vec(), generation);
        next.set.generation = generation;
        Ok(next)
    }

    /// Explicit corrected profile. Does not read a bundle or a saved snapshot.
    pub fn restore_domain(
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
            require_consistent(&pin, &next.set.organizational_root_spki)?;
            if pin.trust_domain != domain || !seen.insert(pin.spki_der.clone()) {
                return Err(AnchorError::InvalidPin(pin.trust_domain.to_string()));
            }
            next.bundle_fenced.remove(&pin.spki_der);
            next.drain_admitted_before
                .insert(pin.spki_der.clone(), generation);
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
        if !candidate.by_domain.contains_key(&candidate.local_domain) {
            return Err(AnchorError::UntrustedTrustDomain(
                candidate.local_domain.to_string(),
            ));
        }
        for pins in candidate.by_domain.values() {
            for pin in pins {
                let cert = strict_cert(pin.der.as_ref())?;
                let spki = cert.public_key().raw.to_vec();
                if self.bundle_fenced.contains(&spki) {
                    return Err(AnchorError::WithdrawnSnapshot {
                        candidate: candidate.generation,
                    });
                }
                require_consistent(pin, &candidate.organizational_root_spki)?;
            }
        }
        let mut next = self.clone();
        next.set = candidate;
        Ok(next)
    }

    /// Inspect a bundle. The publication is not modified.
    pub fn observe_bundle(
        &self,
        domain: &Strng,
        fetched: BundleFetch,
        now: SystemTime,
    ) -> BundleObservation {
        let BundleFetch::Authorities(authority_ders) = fetched else {
            return BundleObservation::Unavailable;
        };
        match admit_domain_authorities(self, domain, &authority_ders, now) {
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

fn strict_cert(der: &[u8]) -> Result<X509Certificate<'_>, AnchorError> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| AnchorError::BadEncoding)?;
    if !rest.is_empty() {
        return Err(AnchorError::TrailingBytes);
    }
    Ok(cert)
}

fn require_signing_ca(cert: &X509Certificate<'_>) -> Result<(), AnchorError> {
    let basic = cert
        .basic_constraints()
        .map_err(|_| AnchorError::BadEncoding)?;
    let Some(basic) = basic else {
        return Err(AnchorError::NotCertificateAuthority);
    };
    if !basic.value.ca {
        return Err(AnchorError::NotCertificateAuthority);
    }
    let usage = cert.key_usage().map_err(|_| AnchorError::BadEncoding)?;
    let Some(usage) = usage else {
        return Err(AnchorError::InvalidKeyUsage);
    };
    if !usage.value.key_cert_sign() {
        return Err(AnchorError::InvalidKeyUsage);
    }
    Ok(())
}

fn reject_ca_leaf(cert: &X509Certificate<'_>) -> Result<(), AnchorError> {
    let basic = cert
        .basic_constraints()
        .map_err(|_| AnchorError::BadEncoding)?;
    if basic.is_some_and(|extension| extension.value.ca) {
        return Err(AnchorError::NotALeaf);
    }
    let usage = cert.key_usage().map_err(|_| AnchorError::BadEncoding)?;
    if usage.is_some_and(|extension| extension.value.key_cert_sign()) {
        return Err(AnchorError::NotALeaf);
    }
    Ok(())
}

fn encoded_bounds(cert: &X509Certificate<'_>) -> Result<(SystemTime, SystemTime), AnchorError> {
    let validity = cert.validity();
    Ok((
        system_time_from_unix(validity.not_before.timestamp())?,
        system_time_from_unix(validity.not_after.timestamp())?,
    ))
}

fn system_time_from_unix(secs: i64) -> Result<SystemTime, AnchorError> {
    let secs = u64::try_from(secs).map_err(|_| AnchorError::BadEncoding)?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or(AnchorError::BadEncoding)
}

fn check_profile_window(
    encoded_not_before: SystemTime,
    encoded_not_after: SystemTime,
    profile_not_after: SystemTime,
) -> Result<(), AnchorError> {
    if profile_not_after > encoded_not_after {
        return Err(AnchorError::ProfileExtendsAuthority {
            encoded_not_after,
            profile_not_after,
        });
    }
    if profile_not_after <= encoded_not_before {
        return Err(AnchorError::ProfileOutsideAuthority {
            encoded_not_before,
            profile_not_after,
        });
    }
    Ok(())
}

fn verified_root_spki(root: &AuthenticatedRoot) -> Result<Vec<u8>, AnchorError> {
    let cert = strict_cert(root.der.as_ref())?;
    require_signing_ca(&cert)?;
    let spki = cert.public_key().raw.to_vec();
    if spki != root.spki_der {
        return Err(AnchorError::InconsistentPin);
    }
    Ok(spki)
}

fn require_consistent(pin: &DomainPin, root_spki: &[u8]) -> Result<(), AnchorError> {
    let cert = strict_cert(pin.der.as_ref())?;
    require_signing_ca(&cert)?;
    let spki = cert.public_key().raw.to_vec();
    let (encoded_not_before, encoded_not_after) = encoded_bounds(&cert)?;
    if spki != pin.spki_der
        || encoded_not_before != pin.encoded_not_before
        || encoded_not_after != pin.encoded_not_after
    {
        return Err(AnchorError::InconsistentPin);
    }
    check_profile_window(
        encoded_not_before,
        encoded_not_after,
        pin.profile_not_after,
    )?;
    if spki == root_spki {
        return Err(AnchorError::RejectedRoot {
            domain: pin.trust_domain.to_string(),
        });
    }
    Ok(())
}

fn pin_time(pin: &DomainPin, now: SystemTime) -> Result<(), AnchorError> {
    if now < pin.encoded_not_before || now >= pin.encoded_not_after {
        return Err(AnchorError::AuthorityExpired {
            domain: pin.trust_domain.to_string(),
        });
    }
    if now >= pin.profile_not_after {
        return Err(AnchorError::ProfileStale {
            domain: pin.trust_domain.to_string(),
        });
    }
    Ok(())
}

fn observed_at(now: UnixTime) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(now.as_secs())
}

/// Supported peer profile: exactly one URI SAN, and that URI is
/// `spiffe://<non-empty trust domain>/ns/<non-empty namespace>/sa/<non-empty service account>`.
/// Every SAN entry is examined. One parseable SPIFFE URI does not hide another URI,
/// a DNS name, an email name, or an empty path segment.
fn supported_identity(cert: &X509Certificate<'_>) -> Result<Identity, AnchorError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|_| AnchorError::MalformedSan)?;
    let Some(san) = san else {
        return Err(AnchorError::MalformedSan);
    };
    if san.value.general_names.is_empty() {
        return Err(AnchorError::MalformedSan);
    }
    let mut identity = None;
    let mut unsupported = false;
    for name in &san.value.general_names {
        match name {
            GeneralName::URI(uri) => {
                let parsed = supported_spiffe(uri)?;
                if identity.is_some() {
                    return Err(AnchorError::AmbiguousSan);
                }
                identity = Some(parsed);
            }
            GeneralName::Invalid(_, _) => return Err(AnchorError::MalformedSan),
            _ => unsupported = true,
        }
    }
    if unsupported {
        return Err(AnchorError::UnsupportedSan);
    }
    identity.ok_or(AnchorError::MalformedSan)
}

fn supported_spiffe(uri: &str) -> Result<Identity, AnchorError> {
    let identity = Identity::from_str(uri).map_err(|_| AnchorError::MalformedSan)?;
    let Some(path) = uri.strip_prefix("spiffe://") else {
        return Err(AnchorError::MalformedSan);
    };
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 5
        || parts[0].is_empty()
        || parts[1] != "ns"
        || parts[2].is_empty()
        || parts[3] != "sa"
        || parts[4].is_empty()
        || identity.to_string() != uri
    {
        return Err(AnchorError::MalformedSan);
    }
    Ok(identity)
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

pub fn verify_peer_certificate(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    let cert = strict_cert(end.as_ref())?;
    reject_ca_leaf(&cert)?;
    let identity = supported_identity(&cert)?;
    let domain = identity.trust_domain();
    let Some(pins) = anchors.by_domain.get(&domain) else {
        return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
    };
    let observed = observed_at(now);
    let mut matched = 0usize;
    let mut time_error = None;
    for pin in pins {
        match pin_time(pin, observed) {
            Ok(()) => {
                if path_accepts(end, intermediates, pin, now, role) {
                    matched += 1;
                }
            }
            Err(error) => time_error = Some(error),
        }
    }
    let mut foreign = false;
    for (other, other_pins) in &anchors.by_domain {
        if other == &domain {
            continue;
        }
        for pin in other_pins {
            if pin_time(pin, observed).is_ok() && path_accepts(end, intermediates, pin, now, role)
            {
                foreign = true;
            }
        }
    }
    if foreign {
        return Err(AnchorError::AmbiguousIssuer(domain.to_string()));
    }
    if matched == 1 {
        return Ok(identity);
    }
    if matched == 0 {
        if let Some(error) = time_error {
            return Err(error);
        }
    }
    Err(AnchorError::UnauthorizedIssuer(domain.to_string()))
}

pub fn verify_expected_identity(
    end: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    anchors: &DomainAnchorSet,
    expected: &[Identity],
    now: UnixTime,
    role: PeerRole,
) -> Result<Identity, AnchorError> {
    let identity = verify_peer_certificate(end, intermediates, anchors, now, role)?;
    if expected.iter().any(|want| want == &identity) {
        Ok(identity)
    } else {
        Err(AnchorError::UnexpectedPeer {
            authenticated: identity.to_string(),
        })
    }
}

fn constraints_differ(
    approved: &X509Certificate<'_>,
    presented: &X509Certificate<'_>,
) -> Result<bool, AnchorError> {
    let approved = approved
        .name_constraints()
        .map_err(|_| AnchorError::BadEncoding)?;
    let presented = presented
        .name_constraints()
        .map_err(|_| AnchorError::BadEncoding)?;
    match (approved, presented) {
        (None, None) => Ok(false),
        (Some(approved), Some(presented)) => Ok(approved.value != presented.value),
        _ => Ok(true),
    }
}

fn substitution_error(
    domain: &Strng,
    approved: &X509Certificate<'_>,
    presented: &X509Certificate<'_>,
) -> Result<AnchorError, AnchorError> {
    if approved.subject().as_raw() != presented.subject().as_raw() {
        return Ok(AnchorError::SubstitutedSubject {
            domain: domain.to_string(),
        });
    }
    let approved_validity = approved.validity();
    let presented_validity = presented.validity();
    if approved_validity.not_before.timestamp() != presented_validity.not_before.timestamp()
        || approved_validity.not_after.timestamp() != presented_validity.not_after.timestamp()
    {
        return Ok(AnchorError::SubstitutedExpiry {
            domain: domain.to_string(),
        });
    }
    if constraints_differ(approved, presented)? {
        return Ok(AnchorError::SubstitutedConstraints {
            domain: domain.to_string(),
        });
    }
    Ok(AnchorError::SubstitutedCertificate {
        domain: domain.to_string(),
    })
}

pub fn admit_domain_authorities(
    publication: &AnchorPublication,
    domain: &Strng,
    authority_ders: &[CertificateDer<'static>],
    now: SystemTime,
) -> Result<Vec<CertificateDer<'static>>, AnchorError> {
    if authority_ders.is_empty() {
        return Err(AnchorError::MissingCurrentPin {
            domain: domain.to_string(),
        });
    }
    let pins = publication.set.by_domain.get(domain);
    let mut canonical = Vec::new();
    let mut saw_current = false;
    let mut time_error = None;
    for presented_der in authority_ders {
        let presented = strict_cert(presented_der.as_ref())?;
        let spki = presented.public_key().raw.to_vec();
        if publication.bundle_fenced.contains(&spki) {
            return Err(AnchorError::WithdrawnIssuer {
                domain: domain.to_string(),
            });
        }
        if spki == publication.set.organizational_root_spki {
            return Err(AnchorError::RejectedRoot {
                domain: domain.to_string(),
            });
        }
        let Some(pins) = pins else {
            return Err(AnchorError::UntrustedTrustDomain(domain.to_string()));
        };
        if let Some(pin) = pins.iter().find(|pin| pin.der.as_ref() == presented_der.as_ref()) {
            match pin_time(pin, now) {
                Ok(()) => {
                    canonical.push(pin.der.clone());
                    saw_current = true;
                }
                Err(error) => time_error = Some(error),
            }
            continue;
        }
        if let Some(pin) = pins.iter().find(|pin| pin.spki_der == spki) {
            let approved = strict_cert(pin.der.as_ref())?;
            return Err(substitution_error(domain, &approved, &presented)?);
        }
        return Err(AnchorError::UnpinnedAuthority {
            domain: domain.to_string(),
        });
    }
    if !saw_current {
        return Err(time_error.unwrap_or(AnchorError::MissingCurrentPin {
            domain: domain.to_string(),
        }));
    }
    Ok(canonical)
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
        .any(|pin| pin.spki_der == tunnel.signer_spki && pin_time(pin, now).is_ok())
    {
        RetainedDecision::Keep
    } else {
        RetainedDecision::Drain
    }
}

pub fn signer_deadline(anchors: &DomainAnchorSet, signer_spki: &[u8]) -> Option<SystemTime> {
    anchors.by_domain.values().flatten().find_map(|pin| {
        (pin.spki_der == signer_spki).then_some(pin.profile_not_after.min(pin.encoded_not_after))
    })
}

/// `Keep` leaves the socket open. `Drain` shuts it down. The HBONE pool does not call this yet.
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
        GeneralSubtree, IsCa, KeyPair, KeyUsagePurpose, NameConstraints, SanType,
    };
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const DOMAIN_A: &str = "cmtc-a.mesh.example";
    const DOMAIN_B: &str = "cmtc-b.mesh.example";
    const URI_A: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/api";
    const URI_B: &str = "spiffe://cmtc-b.mesh.example/ns/orders/sa/api";
    const URI_A_OTHER: &str = "spiffe://cmtc-a.mesh.example/ns/orders/sa/other";
    const T0: u64 = 1_700_000_000;

    struct Fixture {
        root: AuthenticatedRoot,
        profile: DomainAnchorSet,
        root_der: CertificateDer<'static>,
        ica_a_der: CertificateDer<'static>,
        ica_b_der: CertificateDer<'static>,
        ica_a_spki: Vec<u8>,
        ica_b_pin: DomainPin,
        ica_a_key_der: Vec<u8>,
        root_issuer_key_der: Vec<u8>,
        leaf_a_by_a: CertificateDer<'static>,
        leaf_a_by_b: CertificateDer<'static>,
        leaf_a_by_root: CertificateDer<'static>,
        leaf_b_by_b: CertificateDer<'static>,
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

    fn leaf_params(uris: &[&str], extra_dns: Option<&str>) -> CertificateParams {
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
            let ia5 = Ia5String::try_from(*uri).expect("uri");
            params.subject_alt_names.push(SanType::URI(ia5));
        }
        if let Some(dns) = extra_dns {
            let ia5 = Ia5String::try_from(dns).expect("dns");
            params.subject_alt_names.push(SanType::DnsName(ia5));
        }
        params
    }

    fn owned_der(der: &CertificateDer<'_>) -> CertificateDer<'static> {
        CertificateDer::from(der.as_ref().to_vec())
    }

    fn reload_key(key: &KeyPair) -> KeyPair {
        KeyPair::try_from(key.serialize_der()).expect("reload pkcs8")
    }

    fn sign_leaf(
        uris: &[&str],
        extra_dns: Option<&str>,
        issuer: &CertifiedIssuer<'_, KeyPair>,
    ) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("leaf key");
        let cert = leaf_params(uris, extra_dns)
            .signed_by(&key, &**issuer)
            .expect("sign leaf");
        owned_der(cert.der())
    }

    fn fixture() -> Fixture {
        let root_key = KeyPair::generate().expect("root key");
        let root_issuer_key_der = root_key.serialize_der();
        let root = CertifiedIssuer::self_signed(ca_params("organizational-root"), root_key)
            .expect("root cert");
        let ica_a_key = KeyPair::generate().expect("intermediate a key");
        let ica_a_key_der = ica_a_key.serialize_der();
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
        let authenticated = AuthenticatedRoot::parse(root_der.clone()).expect("root");
        let pin_a = DomainPin::parse(DOMAIN_A.into(), ica_a_der.clone(), ts(T0 + 100))
            .expect("pin a");
        let pin_b = DomainPin::parse(DOMAIN_B.into(), ica_b_der.clone(), ts(T0 + 100))
            .expect("pin b");
        let profile = DomainAnchorSet::try_new(
            DOMAIN_A.into(),
            &authenticated,
            1,
            vec![pin_a.clone(), pin_b.clone()],
        )
        .expect("profile");
        Fixture {
            root: authenticated,
            profile,
            root_der,
            ica_a_der,
            ica_b_der,
            ica_a_spki: pin_a.spki().to_vec(),
            ica_b_pin: pin_b,
            ica_a_key_der,
            root_issuer_key_der,
            leaf_a_by_a: sign_leaf(&[URI_A], None, &ica_a),
            leaf_a_by_b: sign_leaf(&[URI_A], None, &ica_b),
            leaf_a_by_root: sign_leaf(&[URI_A], None, &root),
            leaf_b_by_b: sign_leaf(&[URI_B], None, &ica_b),
            now: ut(T0),
        }
    }

    fn identity_a() -> Identity {
        Identity::from_str(URI_A).expect("identity a")
    }

    fn identity_b() -> Identity {
        Identity::from_str(URI_B).expect("identity b")
    }

    fn same_subject_key_cert(
        cn: &str,
        key_der: &[u8],
        issuer_key_der: &[u8],
        issuer_params: CertificateParams,
        mutate: impl FnOnce(&mut CertificateParams),
    ) -> CertificateDer<'static> {
        let subject_key = KeyPair::try_from(key_der).expect("subject key");
        let issuer_key = KeyPair::try_from(issuer_key_der).expect("issuer key");
        let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).expect("issuer");
        let mut params = ca_params(cn);
        mutate(&mut params);
        let cert = params.signed_by(&subject_key, &issuer).expect("substitute");
        owned_der(cert.der())
    }

    #[test]
    fn same_namespace_and_account_in_two_domains_are_different() {
        let a = Identity::from_parts(DOMAIN_A.into(), "orders".into(), "api".into());
        let b = Identity::from_parts(DOMAIN_B.into(), "orders".into(), "api".into());
        assert_ne!(a, b);
        assert!(
            Identity::from_str("spiffe://cmtc-a.mesh.example/cluster/a/ns/orders/sa/api").is_err()
        );
    }

    #[test]
    fn exact_san_accepts_client_and_server_roles() {
        let fix = fixture();
        for role in [PeerRole::Server, PeerRole::Client] {
            let got = verify_expected_identity(
                &fix.leaf_a_by_a,
                &[],
                &fix.profile,
                &[identity_a()],
                fix.now,
                role,
            )
            .expect("pinned issuer");
            assert_eq!(got, identity_a());
        }
    }

    #[test]
    fn exact_san_rejects_a_different_service_account() {
        let fix = fixture();
        let err = verify_expected_identity(
            &fix.leaf_a_by_a,
            &[],
            &fix.profile,
            &[Identity::from_str(URI_A_OTHER).expect("other")],
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
    fn wrong_domain_signer_is_ambiguous_when_the_root_chain_succeeds() {
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
        .expect("common-root path success is not acceptance");
        let err = verify_peer_certificate(
            &fix.leaf_a_by_b,
            &[],
            &fix.profile,
            fix.now,
            PeerRole::Server,
        )
        .expect_err("domain A signed by domain B");
        assert_eq!(err, AnchorError::AmbiguousIssuer(DOMAIN_A.to_string()));
    }

    #[test]
    fn unknown_signer_direct_root_and_ca_leaf_are_rejected() {
        let fix = fixture();
        let published = AnchorPublication::initial(fix.profile.clone());
        let only_a = published
            .withdraw_pin(&DOMAIN_B.into(), &fix.ica_b_pin.spki(), 2)
            .expect("withdraw B");
        assert_eq!(
            verify_peer_certificate(
                &fix.leaf_a_by_b,
                &[],
                only_a.anchors(),
                fix.now,
                PeerRole::Server,
            )
            .expect_err("unpinned"),
            AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string())
        );
        assert_eq!(
            verify_peer_certificate(
                &fix.leaf_a_by_root,
                &[],
                &fix.profile,
                fix.now,
                PeerRole::Client,
            )
            .expect_err("root signed"),
            AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string())
        );
        assert_eq!(
            verify_peer_certificate(
                &fix.ica_a_der,
                &[],
                &fix.profile,
                fix.now,
                PeerRole::Server,
            )
            .expect_err("intermediate presented as leaf"),
            AnchorError::NotALeaf
        );
    }

    #[test]
    fn root_der_cannot_be_hidden_behind_a_fabricated_spki_or_used_as_a_pin() {
        let fix = fixture();
        let honest_root = DomainPin::parse(DOMAIN_A.into(), fix.root_der.clone(), ts(T0 + 60))
            .expect("root parses as a CA");
        assert_eq!(
            DomainAnchorSet::try_new(DOMAIN_A.into(), &fix.root, 1, vec![honest_root])
                .expect_err("root pin"),
            AnchorError::RejectedRoot {
                domain: DOMAIN_A.to_string(),
            }
        );
        let mut concealed =
            DomainPin::parse(DOMAIN_A.into(), fix.root_der.clone(), ts(T0 + 60)).expect("parse");
        concealed.spki_der = b"fabricated-non-root".to_vec();
        assert_eq!(
            DomainAnchorSet::try_new(DOMAIN_A.into(), &fix.root, 1, vec![concealed])
                .expect_err("fabricated spki"),
            AnchorError::InconsistentPin
        );
        let mut shifted = DomainPin::parse(DOMAIN_A.into(), fix.ica_a_der.clone(), ts(T0 + 60))
            .expect("intermediate");
        shifted.profile_not_after = shifted.encoded_not_after + Duration::from_secs(1);
        assert!(matches!(
            DomainAnchorSet::try_new(DOMAIN_A.into(), &fix.root, 1, vec![shifted])
                .expect_err("tampered deadline"),
            AnchorError::ProfileExtendsAuthority { .. }
        ));
    }

    #[test]
    fn profile_deadline_cannot_extend_encoded_authority_expiry() {
        let fix = fixture();
        let sample = DomainPin::parse(DOMAIN_A.into(), fix.ica_a_der.clone(), ts(T0 + 100))
            .expect("sample");
        let encoded = sample.encoded_not_after();
        assert!(encoded > ts(T0 + 100));
        let err = DomainPin::parse(
            DOMAIN_A.into(),
            fix.ica_a_der.clone(),
            encoded + Duration::from_secs(1),
        )
        .expect_err("extended deadline");
        assert!(matches!(err, AnchorError::ProfileExtendsAuthority { .. }));
        assert_eq!(
            DomainPin::parse(DOMAIN_A.into(), fix.ica_a_der, sample.encoded_not_before())
                .expect_err("deadline at not_before"),
            AnchorError::ProfileOutsideAuthority {
                encoded_not_before: sample.encoded_not_before(),
                profile_not_after: sample.encoded_not_before(),
            }
        );
    }

    #[test]
    fn anchors_must_be_signing_cas_without_trailing_bytes() {
        let fix = fixture();
        let leaf_key = KeyPair::generate().expect("leaf key");
        let issuer_key = KeyPair::try_from(fix.ica_a_key_der.as_slice()).expect("ica key");
        let issuer =
            CertifiedIssuer::self_signed(ca_params("cluster-a-intermediate"), issuer_key)
                .expect("issuer");
        let leaf = leaf_params(&[URI_A], None)
            .signed_by(&leaf_key, &issuer)
            .expect("leaf");
        assert_eq!(
            DomainPin::parse(DOMAIN_A.into(), owned_der(leaf.der()), ts(T0 + 60))
                .expect_err("end entity"),
            AnchorError::NotCertificateAuthority
        );
        let digital_only = KeyPair::generate().expect("digital key");
        let mut digital_params = ca_params("digital-only");
        digital_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let digital =
            CertifiedIssuer::self_signed(digital_params, digital_only).expect("digital ca");
        assert_eq!(
            DomainPin::parse(DOMAIN_A.into(), owned_der(digital.der()), ts(T0 + 60))
                .expect_err("missing keyCertSign"),
            AnchorError::InvalidKeyUsage
        );
        let no_usage_key = KeyPair::generate().expect("no usage key");
        let mut no_usage = ca_params("no-usage");
        no_usage.key_usages.clear();
        let unsigned =
            CertifiedIssuer::self_signed(no_usage, no_usage_key).expect("ca without usage");
        assert_eq!(
            DomainPin::parse(DOMAIN_A.into(), owned_der(unsigned.der()), ts(T0 + 60))
                .expect_err("absent key usage"),
            AnchorError::InvalidKeyUsage
        );
        let mut trailed = fix.ica_a_der.as_ref().to_vec();
        trailed.push(0x00);
        assert_eq!(
            DomainPin::parse(DOMAIN_A.into(), CertificateDer::from(trailed), ts(T0 + 60))
                .expect_err("trailing"),
            AnchorError::TrailingBytes
        );
    }

    #[test]
    fn duplicate_pins_are_rejected_at_construction_and_verification() {
        let fix = fixture();
        let pin = DomainPin::parse(DOMAIN_A.into(), fix.ica_a_der.clone(), ts(T0 + 60))
            .expect("pin");
        assert_eq!(
            DomainAnchorSet::try_new(
                DOMAIN_A.into(),
                &fix.root,
                1,
                vec![pin.clone(), pin.clone()],
            )
            .expect_err("duplicate"),
            AnchorError::InvalidPin(DOMAIN_A.to_string())
        );
        let mut duplicated = fix.profile.clone();
        let domain: Strng = DOMAIN_A.into();
        let again = duplicated
            .by_domain
            .get(&domain)
            .expect("pins")
            .first()
            .expect("pin")
            .clone();
        duplicated
            .by_domain
            .get_mut(&domain)
            .expect("pins")
            .push(again);
        assert_eq!(
            verify_peer_certificate(
                &fix.leaf_a_by_a,
                &[],
                &duplicated,
                fix.now,
                PeerRole::Server,
            )
            .expect_err("two matches"),
            AnchorError::UnauthorizedIssuer(DOMAIN_A.to_string())
        );
    }

    #[test]
    fn one_valid_spiffe_uri_does_not_hide_another_san_entry() {
        let fix = fixture();
        let ica_key = KeyPair::try_from(fix.ica_a_key_der.as_slice()).expect("ica key");
        let ica = CertifiedIssuer::self_signed(ca_params("cluster-a-intermediate"), ica_key)
            .expect("ica");
        let cases = [
            (
                sign_leaf(&[URI_A, "spiffe://not-a-valid-id"], None, &ica),
                AnchorError::MalformedSan,
            ),
            (
                sign_leaf(
                    &["spiffe://cmtc-a.mesh.example/ns//sa/api"],
                    None,
                    &ica,
                ),
                AnchorError::MalformedSan,
            ),
            (
                sign_leaf(&[URI_A], Some("api.orders.svc"), &ica),
                AnchorError::UnsupportedSan,
            ),
            (
                sign_leaf(&[URI_A, URI_A_OTHER], None, &ica),
                AnchorError::AmbiguousSan,
            ),
            (sign_leaf(&[], None, &ica), AnchorError::MalformedSan),
        ];
        for (leaf, expected) in cases {
            let (_, parsed) = X509Certificate::from_der(leaf.as_ref()).expect("parse leaf");
            let helper = super::super::certificate::identities(&parsed).expect("helper");
            assert!(
                helper.len() <= 1,
                "the existing helper kept more than one identity: {helper:?}"
            );
            assert_eq!(
                verify_peer_certificate(&leaf, &[], &fix.profile, fix.now, PeerRole::Server)
                    .expect_err("strict san"),
                expected
            );
        }
        let mut garbage = fix.leaf_a_by_a.as_ref().to_vec();
        garbage.push(0x00);
        assert_eq!(
            verify_peer_certificate(
                &CertificateDer::from(garbage),
                &[],
                &fix.profile,
                fix.now,
                PeerRole::Client,
            )
            .expect_err("trailing leaf"),
            AnchorError::TrailingBytes
        );
    }

    #[test]
    fn bundle_substitution_returns_no_certificate() {
        let fix = fixture();
        let publication = AnchorPublication::initial(fix.profile.clone());
        let domain: Strng = DOMAIN_A.into();
        let subject = same_subject_key_cert(
            "substituted-subject",
            &fix.ica_a_key_der,
            &fix.root_issuer_key_der,
            ca_params("organizational-root"),
            |_| {},
        );
        let expiry = same_subject_key_cert(
            "cluster-a-intermediate",
            &fix.ica_a_key_der,
            &fix.root_issuer_key_der,
            ca_params("organizational-root"),
            |params| {
                params.not_after = time::OffsetDateTime::from_unix_timestamp((T0 + 10) as i64)
                    .expect("expiry");
            },
        );
        let constraints = same_subject_key_cert(
            "cluster-a-intermediate",
            &fix.ica_a_key_der,
            &fix.root_issuer_key_der,
            ca_params("organizational-root"),
            |params| {
                params.name_constraints = Some(NameConstraints {
                    permitted_subtrees: vec![GeneralSubtree::DnsName(
                        "cmtc-a.mesh.example".to_string(),
                    )],
                    excluded_subtrees: vec![],
                });
            },
        );
        let before = publication.anchors().canonical_ders(&domain);
        for (presented, expected) in [
            (subject, AnchorError::SubstitutedSubject { domain: DOMAIN_A.into() }),
            (expiry, AnchorError::SubstitutedExpiry { domain: DOMAIN_A.into() }),
            (
                constraints,
                AnchorError::SubstitutedConstraints { domain: DOMAIN_A.into() },
            ),
        ] {
            assert_ne!(presented.as_ref(), fix.ica_a_der.as_ref());
            assert_eq!(
                admit_domain_authorities(&publication, &domain, &[presented], ts(T0))
                    .expect_err("substitute"),
                expected
            );
        }
        assert_eq!(publication.anchors().canonical_ders(&domain), before);
        let input = CertificateDer::from(fix.ica_a_der.as_ref().to_vec());
        let admitted =
            admit_domain_authorities(&publication, &domain, &[input], ts(T0)).expect("exact");
        assert_eq!(admitted, vec![fix.ica_a_der.clone()]);
        let mut trailed = fix.ica_a_der.as_ref().to_vec();
        trailed.push(0x00);
        assert_eq!(
            admit_domain_authorities(
                &publication,
                &domain,
                &[CertificateDer::from(trailed)],
                ts(T0),
            )
            .expect_err("bundle trailing"),
            AnchorError::TrailingBytes
        );
    }

    #[test]
    fn withdrawal_beats_stale_bundle_partition_and_replay() {
        let fix = fixture();
        let domain_b: Strng = DOMAIN_B.into();
        let published = AnchorPublication::initial(fix.profile.clone());
        let old_bundle = BundleFetch::Authorities(vec![fix.ica_b_der.clone()]);
        assert_eq!(
            published.observe_bundle(&domain_b, old_bundle.clone(), ts(T0)),
            BundleObservation::Consistent
        );
        assert_eq!(
            published
                .withdraw_pin(&domain_b, fix.ica_b_pin.spki(), 1)
                .expect_err("same generation"),
            AnchorError::StaleGeneration { current: 1, candidate: 1 }
        );
        let withdrawn = published
            .withdraw_pin(&domain_b, fix.ica_b_pin.spki(), 2)
            .expect("withdraw before refresh");
        let during_failure = withdrawn.clone();
        assert_eq!(
            withdrawn.observe_bundle(&domain_b, old_bundle, ts(T0)),
            BundleObservation::Rejected(AnchorError::WithdrawnIssuer {
                domain: DOMAIN_B.to_string(),
            })
        );
        assert_eq!(
            withdrawn.observe_bundle(&domain_b, BundleFetch::Unavailable, ts(T0)),
            BundleObservation::Unavailable
        );
        assert_eq!(withdrawn, during_failure);
        assert_eq!(
            withdrawn.replace(fix.profile.clone()).expect_err("generation 1"),
            AnchorError::StaleGeneration { current: 2, candidate: 1 }
        );
        let mut replay = fix.profile.clone();
        replay.generation = 4;
        assert_eq!(
            withdrawn.replace(replay).expect_err("fenced material"),
            AnchorError::WithdrawnSnapshot { candidate: 4 }
        );
        let substitute = same_subject_key_cert(
            "withdrawn-substitute",
            &KeyPair::generate().expect("unused").serialize_der(),
            &fix.root_issuer_key_der,
            ca_params("organizational-root"),
            |_| {},
        );
        let _ = substitute;
        let tunnel_b = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_b(),
            signer_spki: fix.ica_b_pin.spki().to_vec(),
        };
        let tunnel_a = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_a(),
            signer_spki: fix.ica_a_spki.clone(),
        };
        assert_eq!(retained_tunnel(&tunnel_b, &withdrawn, ts(T0)), RetainedDecision::Drain);
        assert_eq!(retained_tunnel(&tunnel_a, &withdrawn, ts(T0)), RetainedDecision::Keep);
        let restored = withdrawn
            .restore_domain(vec![fix.ica_b_pin.clone()], 3)
            .expect("explicit restore");
        assert!(!restored.bundle_fenced(fix.ica_b_pin.spki()));
        verify_expected_identity(
            &fix.leaf_b_by_b,
            &[],
            restored.anchors(),
            &[identity_b()],
            ut(T0),
            PeerRole::Server,
        )
        .expect("new handshake");
        assert_eq!(retained_tunnel(&tunnel_b, &restored, ts(T0)), RetainedDecision::Drain);
        let renewed = RetainedTunnel {
            anchor_generation: 3,
            peer: identity_b(),
            signer_spki: fix.ica_b_pin.spki().to_vec(),
        };
        assert_eq!(retained_tunnel(&renewed, &restored, ts(T0)), RetainedDecision::Keep);
    }

    #[test]
    fn profile_and_encoded_deadlines_drain_without_reload() {
        let fix = fixture();
        let published = AnchorPublication::initial(fix.profile.clone());
        let tunnel = RetainedTunnel {
            anchor_generation: 1,
            peer: identity_a(),
            signer_spki: fix.ica_a_spki.clone(),
        };
        let deadline = signer_deadline(published.anchors(), &fix.ica_a_spki).expect("deadline");
        assert_eq!(deadline, ts(T0 + 100));
        let pin = published
            .anchors()
            .by_domain
            .get(&Strng::from(DOMAIN_A))
            .expect("pins")
            .iter()
            .find(|pin| pin.spki() == fix.ica_a_spki.as_slice())
            .expect("pin");
        assert!(pin.encoded_not_after() > deadline);
        assert_eq!(retained_tunnel(&tunnel, &published, ts(T0)), RetainedDecision::Keep);
        let mut roots = RootCertStore::empty();
        roots
            .add_parsable_certificates(std::iter::once(pin.der().clone()));
        verify_cert_chain(
            &fix.leaf_a_by_a,
            &[],
            &roots,
            ut(T0 + 100),
            KeyUsage::server_auth(),
            &[],
        )
        .expect("webpki does not apply the profile deadline to a trust anchor");
        assert_eq!(
            verify_peer_certificate(
                &fix.leaf_a_by_a,
                &[],
                published.anchors(),
                ut(T0 + 100),
                PeerRole::Server,
            )
            .expect_err("profile deadline"),
            AnchorError::ProfileStale { domain: DOMAIN_A.to_string() }
        );
        assert_eq!(
            published.observe_bundle(&DOMAIN_A.into(), BundleFetch::Unavailable, deadline),
            BundleObservation::Unavailable
        );
        assert_eq!(published.generation(), 1);
        assert_eq!(retained_tunnel(&tunnel, &published, deadline), RetainedDecision::Drain);

        let short_key = KeyPair::generate().expect("short key");
        let short_key_der = short_key.serialize_der();
        let mut short_params = ca_params("short-lived-intermediate");
        short_params.not_before =
            time::OffsetDateTime::from_unix_timestamp((T0 - 100) as i64).expect("not before");
        short_params.not_after =
            time::OffsetDateTime::from_unix_timestamp((T0 + 100) as i64).expect("not after");
        let short = CertifiedIssuer::signed_by(short_params, short_key, &{
            let root_key = KeyPair::try_from(fix.root_issuer_key_der.as_slice()).expect("root key");
            CertifiedIssuer::self_signed(ca_params("organizational-root"), root_key).expect("root")
        })
        .expect("short ca");
        let short_der = owned_der(short.der());
        let short_pin =
            DomainPin::parse(DOMAIN_A.into(), short_der.clone(), ts(T0 + 100)).expect("short pin");
        assert_eq!(short_pin.encoded_not_after(), ts(T0 + 100));
        let short_set = DomainAnchorSet::try_new(
            DOMAIN_A.into(),
            &fix.root,
            1,
            vec![short_pin],
        )
        .expect("short set");
        let short_leaf = sign_leaf(&[URI_A], None, &{
            let key = KeyPair::try_from(short_key_der.as_slice()).expect("reload short");
            CertifiedIssuer::self_signed(
                {
                    let mut params = ca_params("short-lived-intermediate");
                    params.not_before = time::OffsetDateTime::from_unix_timestamp((T0 - 100) as i64)
                        .expect("not before");
                    params.not_after = time::OffsetDateTime::from_unix_timestamp((T0 + 100) as i64)
                        .expect("not after");
                    params
                },
                key,
            )
            .expect("signing copy")
        });
        let mut short_roots = RootCertStore::empty();
        short_roots.add_parsable_certificates(std::iter::once(short_der));
        verify_cert_chain(
            &short_leaf,
            &[],
            &short_roots,
            ut(T0 + 100),
            KeyUsage::server_auth(),
            &[],
        )
        .expect("webpki does not apply trust-anchor notAfter");
        assert_eq!(
            verify_peer_certificate(&short_leaf, &[], &short_set, ut(T0 + 100), PeerRole::Server)
                .expect_err("encoded expiry"),
            AnchorError::AuthorityExpired { domain: DOMAIN_A.to_string() }
        );
    }

    #[tokio::test]
    async fn deadline_supervisor_shuts_the_retained_socket_only_when_due() {
        let fix = fixture();
        let deadline = signer_deadline(&fix.profile, &fix.ica_a_spki).expect("deadline");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let mut client = TcpStream::connect(address).await.expect("connect");
        let (mut server, _) = listener.accept().await.expect("accept");
        let supervisor = DeadlineSupervisor::at(deadline);
        let keep = supervisor.decision(ts(T0));
        assert_eq!(
            apply_retention(&mut server, keep).await.expect("keep"),
            RetainedDecision::Keep
        );
        client.write_all(b"canary").await.expect("write");
        let mut buf = [0u8; 6];
        server.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"canary");
        let drain = supervisor.decision(deadline);
        assert_eq!(
            apply_retention(&mut server, drain).await.expect("drain"),
            RetainedDecision::Drain
        );
        let mut after = [0u8; 1];
        assert_eq!(client.read(&mut after).await.expect("client read"), 0);
    }
}
```

The substitution helper signs with a reloaded copy of the intermediate key and a reloaded organizational root. `CertificateParams::signed_by` takes the subject public key separately from the issuer, which is the rcgen 0.14.9 signature. `KeyPair::try_from(&[u8])` accepts the PKCS#8 bytes from `serialize_der` when the `crypto` feature is on. The dev-dependency already enables it. The short-lived expiry test rebuilds the signer with `CertifiedIssuer::self_signed` because the original key was consumed. That certificate is a different issuer object with the same key, so the leaf SPKI path matches the pin.

`same_subject_key_cert` for the withdrawn-substitute assertion currently builds a certificate with a fresh key and discards it. That does not prove the withdrawn key. Replace that unused block with a certificate signed by `fix.ica_a_key_der` only if the test is asserting A. For B, the fixture does not retain B's PKCS#8. The exact `ica_b_der` already hits `WithdrawnIssuer`. Delete the unused substitute in `withdrawal_beats_stale_bundle_partition_and_replay` before copying, and keep the exact-DER assertion. The block below is the replacement for that unused portion:

```rust
        let substitute_b = {
            let presented = CertificateDer::from(fix.ica_b_der.as_ref().to_vec());
            assert_eq!(
                admit_domain_authorities(&withdrawn, &domain_b, &[presented], ts(T0))
                    .expect_err("stale exact der"),
                AnchorError::WithdrawnIssuer {
                    domain: DOMAIN_B.to_string(),
                }
            );
        };
        let _ = substitute_b;
```

That replacement is part of the file to copy: the primary should use it instead of the `KeyPair::generate` discard. A same-key subject substitute for B is not in this fixture because B's private key is not retained. A's subject, expiry, and constraint substitutes are covered by `bundle_substitution_returns_no_certificate`.

### `/private/tmp/cmtc-ztunnel-upstream/src/rbac.rs`

Insert this immediately before `#[cfg(test)]`. It does not call `matches` and it does not remove port, address, or namespace predicates.

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
/// evaluates the same value with `Authorization::matches`.
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

Insert this immediately before the closing brace of `mod tests`. `StringMatch::matches_principal` strips `spiffe://` before the exact comparison. `deny_wins` only calls `Authorization::matches` in the deny-then-allow order used by `DemandProxyState::assert_rbac`. `assert_rbac` is not changed.

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

    fn deny_wins(denies: &[Authorization], allows: &[Authorization], conn: &Connection) -> bool {
        for policy in denies {
            if policy.matches(conn) {
                return false;
            }
        }
        allows.iter().any(|policy| policy.matches(conn))
    }

    #[test]
    fn pinned_profile_keeps_port_namespace_address_and_deny() {
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
                destination_ips: vec![IpNet::new("10.0.0.2".parse().expect("dst"), 32).expect("dst net")],
                source_ips: vec![IpNet::new("10.0.0.1".parse().expect("src"), 32).expect("src net")],
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
        let mut other_source = profile_conn(80, peer.clone());
        other_source.src = "10.0.0.9:40000".parse().expect("other src");
        assert!(!mixed.matches(&other_source));

        let deny = Authorization {
            action: RbacAction::Deny,
            name: "deny-80".into(),
            ..allow.clone()
        };
        screen_pinned_profile(&deny, false).expect("deny is not rewritten");
        let on_80 = profile_conn(80, peer);
        assert!(deny.matches(&on_80));
        assert!(allow.matches(&on_80));
        assert!(!deny_wins(&[deny], &[allow], &on_80));
    }

    #[test]
    fn label_constraint_and_service_account_grant_are_rejected_before_matching() {
        let allow = principal_port(80);
        assert_eq!(
            screen_pinned_profile(&allow, true).expect_err("labels"),
            ProfilePolicyError::PodLabelRequiresDatapath
        );
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
        assert_eq!(
            screen_pinned_profile(&sa_allow, false).expect_err("sa grant"),
            ProfilePolicyError::ServiceAccountGrant
        );
        assert!(sa_allow.matches(&profile_conn(80, orders_api("cmtc-a.mesh.example"))));
        assert!(sa_allow.matches(&profile_conn(80, orders_api("cmtc-b.mesh.example"))));
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
        assert_eq!(
            screen_pinned_profile(&allow_policy("empty", vec![vec![]]), false).expect_err("empty"),
            ProfilePolicyError::EmptyClause
        );
    }
```

## Commands

From `/private/tmp/cmtc-ztunnel-upstream`, after the edits. These commands were not run.

```sh
cargo fmt --check -- src/tls/domain_anchors.rs src/tls.rs src/rbac.rs
RUST_BACKTRACE=1 cargo test --lib domain_anchors --lib rbac -- --test-threads=8
```

No `Cargo.toml` change. Default features remain `tls-aws-lc` and `jemalloc`. Dev-dependencies already include `rcgen` 0.14 with `pem`, `x509-parser`, and `crypto`, `x509-parser` 0.18 with `verify`, and `time` 0.3. Pass the same `FEATURES` value from `Makefile.core.mk` when `TLS_MODE` is set.

```sh
RUST_BACKTRACE=1 cargo test --benches --tests --bins
cargo clippy --benches --tests --bins
```

Do not make the wrong-signer test pass by placing the organizational root and every intermediate in one `RootCertStore`. That test requires `verify_cert_chain` to the root to succeed and `verify_peer_certificate` to return `AmbiguousIssuer`.

## What this slice covers, and the deferred gates

Covered once the primary compiles the tests:

- SPKI, encoded validity, CA bit, and `keyCertSign` come from the certificate bytes. Trailing DER, a non-CA, a CA without `keyCertSign`, a profile deadline past `notAfter`, a root pin, and a root DER with a replaced SPKI are rejected.
- Exact SAN for client and server. A second URI, an empty namespace, a DNS SAN, and a missing SAN fail. The existing identity helper's filtered result is asserted and is not the accept path.
- Same-key subject, expiry, and name-constraint substitutes are rejected. The exact bundle certificate returns the configured DER.
- Withdrawal at a newer generation rejects the old bundle, `BundleFetch::Unavailable`, generation 1, and a generation-4 copy that still contains the fenced certificate. The withdrawn tunnel drains. The other domain's tunnel stays. Explicit `restore_domain` allows a new handshake and still drains the pre-restore tunnel.
- Profile freshness and encoded anchor `notAfter` fail verification and drain retained admission while `verify_cert_chain` still succeeds, with no generation change and no reload.
- `apply_retention` shuts a loopback TCP socket at the pin deadline and leaves it open before that deadline.
- Accepted policies still go through `Authorization::matches`, including port, namespace, source address, destination address, and deny-before-allow. Label and service-account allows are rejected by the screen.

Deferred integration gates, not implemented and not passed:

- `TrustDomainVerifier::verify_client_cert`, `IdentityVerifier::verify_server_cert`, `SpireClient::get_bundle`, and `WorkloadHBONEPool` do not call this module. `InboundCertProvider::fetch_cert` still builds peer trust from `self.root_store`. The local-domain `None` skip in `TrustDomainVerifier` remains.
- `drive_connection` does not call `apply_retention` or `retained_tunnel`. The socket test is the gate function on a loopback TCP connection, not an HBONE multiplex.
- `DemandProxyState::assert_rbac` does not call `screen_pinned_profile`.
- Cilium policy compilation, authenticated remote discovery, CNI `PersistRequired`, WireGuard, IPsec, and the eBPF observer are not in this copy.

Smallest wiring slice, still not code here: pass the publication into the two verifiers and `get_bundle`; call `withdraw_pin` before the SPIRE read; store `RetainedTunnel` on each pooled tunnel and call `apply_retention` from `drive_connection`; call `screen_pinned_profile` before a policy is inserted, then keep `assert_rbac`. Do not change `validateConfig`.

## TLS 1.3 evidence, when a later lab stage runs

An ordinary TLS 1.3 capture encrypts the handshake certificate. Do not treat a missing cleartext certificate in that capture as an identity result, and do not enable session-key logging or copy private keys to produce one. Bind the encrypted HBONE packet metadata and the absence or presence of the application canary to the proxy authentication and policy log for that flow, plus a separately exported public leaf, intermediate, issuer name, and SPKI.

## Unreviewed inputs

`docs/research/cursor/inputs/UNREVIEWED_EBPF_PROPOSAL.md` stays unaccepted. Its Cilium pin predates `06501473`, and that commit only adds the membership epoch. Do not attach it, and do not change the unprivileged Observe DaemonSet.

`cmtc-required-intent-proposal.go.txt` and the adjacent test proposals must not replace `pkg/ztunnel/admission/intent_store_linux.go`. `PersistRequired` is not on the CNI success path. `List` is intent only.

## Ledger for the rest of `docs/research/cursor/FULL_CODE_REQUEST.md`

These stages remain future gates. A green `domain_anchors` or `rbac` log does not start them and does not open the ClusterMesh guard.

1. **Wire this module.** The call sites named above. Future tests must drive a1. **Wire this module.** The call sites named above. Future tests must drive a foreign signer through `server_config` and `outbound_connector`, show `withdraw_pin` draining the matching pooled tunnel while SPIRE is unavailable, and show `screen_pinned_profile` refusing installation before `assert_rbac`. The ClusterMesh guard stays closed.

2. **SPIRE registration.** No registration client exists. `pkg/ztunnel/ca/ca_server.go` `CreateCertificate` must not become the protected issuer. A future gate refuses a trust domain other than the publication’s local domain and refuses an entry without a namespace UID and a pod UID. Evidence is the SPIRE entry list and a denied foreign-domain request, without private keys.

3. **Remote discovery.** `IPIdentityPair` has a pod UID and a service account, not a namespace UID or a policy generation. `IPIdentityWatcher::OnUpdate` does not copy the service account. Sync callbacks run once, and `wsmCommon.Register` overwrites a duplicate prefix. A future gate requires an authenticated origin, a sync epoch, ordered deletes, address and UID reuse, partition expiry, and reconnect that does not resurrect a deleted UID. Stale ipcache is not authorization.

4. **Cilium policy compilation.** The screen rejects label and service-account allows. The future compiler must keep an explicit Cilium deny, a pod-label difference, a named port, and an application port on the datapath or in the unchanged `matches` input. Unsupported L7, FQDN, and CIDR stay out. Missing, NACKed, and stale policy deny. A plaintext deny is independent of a port allowlist.

5. **Durable admission.** Call the existing `OpenIntentStore` and `PersistRequired` before CNI success. Do not replace `pkg/ztunnel/admission/intent_store_linux.go`. Restart uses `List` as intent only, then revalidates the live sandbox and holds the first packet. Corruption, directory-sync poison, an API outage, a late ACK, and UID reuse fail closed. A readiness log is not this gate.

6. **WireGuard and IPsec, separately.** Both directions, Global Service and direct pod IP, TCP 80, 8080, and 31337. A missing required layer blocks the flow. Encrypted packet metadata, the exported public chain and SPKI, the proxy identity, and the policy verdict name the same flow. Current encryption-disabled reachability is not this evidence.

7. **Observe-first eBPF, then deny, then Cilium-native.** Use a separate privileged binary. Reject legacy TC, netkit, and a node without TCX. Do not move Cilium’s tail anchor. Counters are pre-verdict packets and bytes. Deny waits until stage 5 is qualified.

8. **Dashboards.** Keep the nine original JSON files and the Operations and Workload Security pages. Planned series stay planned. Attempts, rejections, mTLS TCP connections, HTTP requests, and TLS handshakes stay distinct. Capture both themes after a real load. No panel is added here.

`validateConfig` remains until stages 1 through 6 have implementation and the evidence above. Stages 7 and 8 do not open it. A unit log from `domain_anchors` or `rbac` is not Protected status.

Before copying `domain_anchors.rs`, replace the unused substitute at the end of `withdrawal_beats_stale_bundle_partition_and_replay` with this. The fixture does not retain cluster B’s private key, so the stale exact certificate is the withdrawal assertion. Same-key subject, expiry, and name-constraint substitution for a live pin is already in `bundle_substitution_returns_no_certificate`.

```rust
        assert_eq!(
            admit_domain_authorities(
                &withdrawn,
                &domain_b,
                &[CertificateDer::from(fix.ica_b_der.as_ref().to_vec())],
                ts(T0),
            )
            .expect_err("stale exact der"),
            AnchorError::WithdrawnIssuer {
                domain: DOMAIN_B.to_string(),
            }
        );
```
