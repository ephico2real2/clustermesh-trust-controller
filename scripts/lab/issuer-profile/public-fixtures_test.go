package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"
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
