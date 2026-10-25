package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
)

func TestPublicOnly(t *testing.T) {
	b, e := generate(time.Now())
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("private material emitted")
	}
	a := b.Approvals["valid"]
	rb, _ := pem.Decode([]byte(a.Roots[0].CertificatePEM))
	r, e := x509.ParseCertificate(rb.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range a.Clusters {
		ib, _ := pem.Decode([]byte(c.Issuers[0].CertificatePEM))
		i, e := x509.ParseCertificate(ib.Bytes)
		if e != nil {
			t.Fatal(e)
		}
		if e = i.CheckSignatureFrom(r); e != nil {
			t.Fatal(e)
		}
		if digest(i.RawSubjectPublicKeyInfo) != c.Issuers[0].SPKISHA256 {
			t.Fatal("SPKI pin")
		}
	}
	if b.RootPin != digest(r.Raw) {
		t.Fatal("root pin")
	}
	if a.Clusters[0].Issuers[0].SPKISHA256 == a.Clusters[1].Issuers[0].SPKISHA256 {
		t.Fatal("issuer reuse")
	}
}

func TestParentedFixtureUsesExplicitClusterCAAndSPIREHint(t *testing.T) {
	now := time.Now().UTC()
	b, err := generateHierarchy(now, true)
	if err != nil {
		t.Fatal(err)
	}
	for variant, a := range b.Approvals {
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "PRIVATE KEY") {
			t.Fatal("fixture exported private key")
		}
		_, err = trustprofile.Validate(raw, []string{b.RootPin}, "cmtc-a", now)
		if (variant == "valid") != (err == nil) {
			t.Fatalf("%s unexpected approval validation: %v", variant, err)
		}
	}
	for _, c := range b.Approvals["valid"].Clusters {
		pin := c.Issuers[0]
		pb, rest := pem.Decode([]byte(pin.ChainPEM))
		if pb == nil || len(rest) != 0 {
			t.Fatal("expected exactly one parent")
		}
		parent, err := x509.ParseCertificate(pb.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		ib, _ := pem.Decode([]byte(pin.CertificatePEM))
		signer, err := x509.ParseCertificate(ib.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if err = signer.CheckSignatureFrom(parent); err != nil {
			t.Fatal(err)
		}
		if parent.MaxPathLen != 1 || len(signer.URIs) != 1 || signer.URIs[0].String() != "spiffe://"+c.TrustDomain {
			t.Fatal("incorrect parent depth or SPIRE CA hint")
		}
	}
}
