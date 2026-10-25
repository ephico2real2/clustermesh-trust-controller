// Run with go run public-fixtures.go. Private CA keys exist only in this process.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"
)

type root struct {
	CertificatePEM string `json:"certificatePEM"`
	SHA256         string `json:"sha256"`
}
type issuer struct {
	CertificatePEM string `json:"certificatePEM"`
	SPKISHA256     string `json:"spkiSHA256"`
	RootSHA256     string `json:"rootSHA256"`
}
type cluster struct {
	ClusterID   string   `json:"clusterID"`
	TrustDomain string   `json:"trustDomain"`
	Issuers     []issuer `json:"issuers"`
}
type approval struct {
	SchemaVersion int       `json:"schemaVersion"`
	Generation    uint64    `json:"generation"`
	ExpiresAt     string    `json:"expiresAt"`
	Roots         []root    `json:"roots"`
	Clusters      []cluster `json:"clusters"`
}
type bundle struct {
	RootPin   string              `json:"rootPin"`
	Approvals map[string]approval `json:"approvals"`
}

func digest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func cert(t, parent *x509.Certificate, key *ecdsa.PrivateKey, parentKey *ecdsa.PrivateKey) (*x509.Certificate, string, error) {
	b, e := x509.CreateCertificate(rand.Reader, t, parent, &key.PublicKey, parentKey)
	if e != nil {
		return nil, "", e
	}
	c, e := x509.ParseCertificate(b)
	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})), e
}
func makeApproval(now time.Time) (approval, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return approval{}, e
	}
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CMTC disposable approval root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rc, rpem, e := cert(rt, rt, key, key)
	if e != nil {
		return approval{}, e
	}
	pin := digest(rc.Raw)
	a := approval{1, 1, now.Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339), []root{{rpem, pin}}, nil}
	for i, name := range []string{"cmtc-a", "cmtc-b"} {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return approval{}, err
		}
		it := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "CMTC disposable " + name + " direct issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(36 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		ic, ipem, err := cert(it, rc, k, key)
		if err != nil {
			return approval{}, err
		}
		a.Clusters = append(a.Clusters, cluster{name, name + ".mesh", []issuer{{ipem, digest(ic.RawSubjectPublicKeyInfo), pin}}})
	}
	return a, nil
}
func generate(now time.Time) (bundle, error) {
	a, e := makeApproval(now)
	if e != nil {
		return bundle{}, e
	}
	other, e := makeApproval(now)
	if e != nil {
		return bundle{}, e
	}
	clone := func(x approval) approval {
		b, _ := json.Marshal(x)
		var y approval
		_ = json.Unmarshal(b, &y)
		return y
	}
	// A fully valid alternate public chain is unapproved by the installed root pin.
	wrong := other
	dup := clone(a)
	dup.Clusters[1].Issuers = append([]issuer(nil), dup.Clusters[0].Issuers...)
	expired := clone(a)
	expired.ExpiresAt = now.Add(-time.Minute).UTC().Truncate(time.Second).Format(time.RFC3339)
	return bundle{a.Roots[0].SHA256, map[string]approval{"valid": a, "wrong-root": wrong, "duplicate-key": dup, "expired": expired}}, nil
}
func main() {
	nowFlag := flag.String("now", "", "Optional RFC3339 fixture clock (default actual UTC)")
	flag.Parse()
	now := time.Now().UTC()
	if *nowFlag != "" {
		var e error
		now, e = time.Parse(time.RFC3339, *nowFlag)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(2)
		}
	}
	b, e := generate(now)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(true)
	if e = enc.Encode(b); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
