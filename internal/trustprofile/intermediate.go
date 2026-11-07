package trustprofile

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"
)

var commonNameOID = asn1.ObjectIdentifier{2, 5, 4, 3}

// IntermediateCommonName is the subject the cluster's SPIRE intermediate Certificate requests (charts/cmtc
// trust.yaml). It binds the certificate to its cluster.
func IntermediateCommonName(cluster string) string { return cluster + " SPIRE intermediate CA" }

// ParseRoot returns the one mesh root certificate in rootPEM when its SHA-256 is an installation-approved pin and it
// is a current, self-signed CA with path depth for an intermediate and a SPIRE CA below it.
func ParseRoot(rootPEM string, rootPins []string, now time.Time) (*x509.Certificate, error) {
	root, err := oneCertificate(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("mesh root: %w", err)
	}
	approved := false
	for _, pin := range rootPins {
		approved = approved || pin == SHA(root.Raw)
	}
	if !approved {
		return nil, errors.New("mesh root is not an installation-approved root pin")
	}
	if err := caCurrent(root, now); err != nil {
		return nil, fmt.Errorf("mesh root: %w", err)
	}
	if !caDepthAllows(root, 2) {
		return nil, errors.New("mesh root path length leaves no room for the intermediate and a SPIRE CA")
	}
	if !bytes.Equal(root.RawSubject, root.RawIssuer) || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("mesh root is not self-signed")
	}
	return root, nil
}

// SPIREIntermediateIssuer derives the approval issuer of one cluster from its SPIRE intermediate certificate, as
// cert-manager issued it under the mesh root. It ports spire_intermediate_issuer of
// scripts/lab/issuer-profile/publish_issuers.py: the verifiers' CA rules (caCurrent, caDepthAllows), the root's
// signature, the cluster's common name and a key distinct from the root's.
func SPIREIntermediateIssuer(cluster, intermediatePEM string, root *x509.Certificate, now time.Time) (Issuer, time.Time, error) {
	if !ClusterValid(cluster) {
		return Issuer{}, time.Time{}, errors.New("invalid cluster name")
	}
	cert, err := oneCertificate(intermediatePEM)
	if err != nil {
		return Issuer{}, time.Time{}, fmt.Errorf("SPIRE intermediate: %w", err)
	}
	if err := caCurrent(cert, now); err != nil {
		return Issuer{}, time.Time{}, fmt.Errorf("SPIRE intermediate: %w", err)
	}
	if !caDepthAllows(cert, 1) {
		return Issuer{}, time.Time{}, errors.New("SPIRE intermediate path length leaves no room for a SPIRE CA")
	}
	if !bytes.Equal(cert.RawIssuer, root.RawSubject) || cert.CheckSignatureFrom(root) != nil {
		return Issuer{}, time.Time{}, errors.New("SPIRE intermediate is not signed by the mesh root")
	}
	var names []string
	for _, attribute := range cert.Subject.Names {
		if attribute.Type.Equal(commonNameOID) {
			value, _ := attribute.Value.(string)
			names = append(names, value)
		}
	}
	if len(names) != 1 || names[0] != IntermediateCommonName(cluster) {
		return Issuer{}, time.Time{}, errors.New("SPIRE intermediate common name differs from its cluster")
	}
	if bytes.Equal(cert.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) {
		return Issuer{}, time.Time{}, errors.New("SPIRE intermediate reuses the root key")
	}
	issuer := Issuer{CertificatePEM: canonical(cert), SPKISHA256: SHA(cert.RawSubjectPublicKeyInfo), RootSHA256: SHA(root.Raw), SignsSPIRECA: true}
	return issuer, cert.NotAfter.UTC(), nil
}

// IssuerNotAfter is the expiry of an approval issuer's certificate.
func IssuerNotAfter(i Issuer) (time.Time, error) {
	cert, err := oneCertificate(i.CertificatePEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter.UTC(), nil
}

// DecodeApproval decodes an approval with the strict key rules of Validate, without its time checks: the arbiter
// reads the generation and issuers of an approval that may have expired.
func DecodeApproval(data []byte) (*Approval, error) {
	var a Approval
	if err := decode(data, &a); err != nil {
		return nil, err
	}
	if a.SchemaVersion != SchemaVersion || a.Generation == 0 {
		return nil, errors.New("invalid approval schema or generation")
	}
	if _, err := parseTime(a.ExpiresAt); err != nil {
		return nil, err
	}
	return &a, nil
}
