package trustprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

type caFixture struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func makeCA(t *testing.T, parent *caFixture, now time.Time, change func(*x509.Certificate)) *caFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "public test issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2}
	if change != nil {
		change(template)
	}
	signer, signingKey := template, key
	if parent != nil {
		signer, signingKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &caFixture{cert: cert, key: key, pem: canonical(cert)}
}
func approvalFixture(t *testing.T) (Approval, []string, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	root := makeCA(t, nil, now, nil)
	a := Approval{SchemaVersion: 1, Generation: 1, ExpiresAt: Stamp(now.Add(time.Hour)), Roots: []Root{{CertificatePEM: root.pem, SHA256: SHA(root.cert.Raw)}}}
	for _, id := range []string{"cmtc-a", "cmtc-b"} {
		issuer := makeCA(t, root, now, nil)
		a.Clusters = append(a.Clusters, Cluster{ClusterID: id, TrustDomain: id + ".mesh", Issuers: []Issuer{{CertificatePEM: issuer.pem, SPKISHA256: SHA(issuer.cert.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256}}})
	}
	return a, []string{a.Roots[0].SHA256}, now
}
func encodeApproval(t *testing.T, a Approval) []byte {
	t.Helper()
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func TestApprovedProfileCanonicalAndClusterBound(t *testing.T) {
	a, pins, now := approvalFixture(t)
	valid, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	a.Clusters[0], a.Clusters[1] = a.Clusters[1], a.Clusters[0]
	a.Roots[0].CertificatePEM = " \n" + a.Roots[0].CertificatePEM + "\n"
	other, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil || valid.Digest != other.Digest {
		t.Fatalf("canonical publication changed: %v", err)
	}
	if _, err := Validate(encodeApproval(t, a), pins, "unknown", now); err == nil {
		t.Fatal("unapproved local cluster accepted")
	}
}
func TestRejectUnapprovedExpiredAmbiguousProfiles(t *testing.T) {
	for _, name := range []string{"wrongRootPin", "wrongIssuerRoot", "duplicateCluster", "duplicateDomain", "duplicateIssuerKey", "rootAsIssuer", "expiredApproval", "expiredCA", "nonCA", "unsupportedCAExtension", "missingIssuer", "multiRoot", "chainNotDirect", "zeroGeneration", "pemPrivate", "pemGarbage", "wrongSPKI", "longCiliumCluster"} {
		t.Run(name, func(t *testing.T) {
			a, pins, now := approvalFixture(t)
			switch name {
			case "wrongRootPin":
				pins = []string{strings.Repeat("0", 64)}
			case "wrongIssuerRoot":
				other := makeCA(t, nil, now, nil)
				a.Roots[0] = Root{CertificatePEM: other.pem, SHA256: SHA(other.cert.Raw)}
				pins = []string{a.Roots[0].SHA256}
				for i := range a.Clusters {
					a.Clusters[i].Issuers[0].RootSHA256 = a.Roots[0].SHA256
				}
			case "duplicateCluster":
				a.Clusters[1].ClusterID = a.Clusters[0].ClusterID
			case "duplicateDomain":
				a.Clusters[1].TrustDomain = a.Clusters[0].TrustDomain
			case "duplicateIssuerKey":
				a.Clusters[1].Issuers = a.Clusters[0].Issuers
			case "rootAsIssuer":
				root, _ := oneCertificate(a.Roots[0].CertificatePEM)
				a.Clusters[0].Issuers[0].CertificatePEM = a.Roots[0].CertificatePEM
				a.Clusters[0].Issuers[0].SPKISHA256 = SHA(root.RawSubjectPublicKeyInfo)
			case "expiredApproval":
				a.ExpiresAt = Stamp(now)
			case "expiredCA":
				now = now.Add(48 * time.Hour)
				a.ExpiresAt = Stamp(now.Add(time.Hour))
			case "nonCA":
				bad := makeCA(t, nil, now, func(c *x509.Certificate) {
					c.IsCA = false
					c.MaxPathLen = -1
					c.MaxPathLenZero = false
					c.KeyUsage = x509.KeyUsageDigitalSignature
				})
				a.Clusters[0].Issuers[0].CertificatePEM = bad.pem
				a.Clusters[0].Issuers[0].SPKISHA256 = SHA(bad.cert.RawSubjectPublicKeyInfo)
			case "unsupportedCAExtension":
				bad := makeCA(t, nil, now, func(c *x509.Certificate) { c.DNSNames = []string{"domain-claim-is-not-authority"} })
				a.Roots[0] = Root{CertificatePEM: bad.pem, SHA256: SHA(bad.cert.Raw)}
				pins = []string{a.Roots[0].SHA256}
			case "missingIssuer":
				a.Clusters[0].Issuers = nil
			case "multiRoot":
				a.Roots = append(a.Roots, a.Roots[0])
			case "chainNotDirect":
				a.Clusters[0].Issuers[0].ChainPEM = a.Roots[0].CertificatePEM
			case "zeroGeneration":
				a.Generation = 0
			case "pemPrivate":
				a.Roots[0].CertificatePEM = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
			case "pemGarbage":
				a.Roots[0].CertificatePEM = "ignored-prefix\n" + a.Roots[0].CertificatePEM
			case "longCiliumCluster":
				a.Clusters[1].ClusterID = strings.Repeat("a", 33)
			case "wrongSPKI":
				a.Clusters[0].Issuers[0].SPKISHA256 = strings.Repeat("0", 64)
			}
			_, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
			if err == nil {
				t.Fatal("unsafe approval accepted")
			}
			if name == "nonCA" && !strings.Contains(err.Error(), "not an explicit signing CA") {
				t.Fatalf("non-CA must fail the actual CA capability check: %v", err)
			}
		})
	}
}
func TestStrictInputAndPublicationDigestLease(t *testing.T) {
	a, pins, now := approvalFixture(t)
	good := encodeApproval(t, a)
	for _, body := range []string{string(good) + " {}", strings.Replace(string(good), `"generation":1`, `"Generation":1`, 1), strings.TrimSuffix(string(good), "}") + `,"generation":1}`, "null", strings.Repeat(" ", MaxBytes+1)} {
		if _, err := Validate([]byte(body), pins, "cmtc-a", now); err == nil {
			t.Fatal("ambiguous JSON accepted")
		}
	}
	valid, err := Validate(good, pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	p := Publication{SchemaVersion: 1, Sequence: 1, State: "published", Reason: "Validated", ProducerCluster: "cmtc-a", OutputUID: "output", ExpectedSourceUID: "source", Source: Source{Namespace: "cmtc-system", Name: "approval", UID: "source", ResourceVersion: "123", Generation: 1}, AcceptedGeneration: 1, AcceptedSourceUID: "source", AcceptedApprovalDigest: valid.Digest, Approval: &valid.Approval, ApprovalDigest: valid.Digest, PublishedAt: Stamp(now), ValidUntil: Stamp(now.Add(MaxLease))}
	body, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{OutputUID: "output", SourceUID: "source", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, RootPins: pins}
	if _, err := VerifyCurrent(body, expected, now); err != nil {
		t.Fatal(err)
	}
	for _, when := range []time.Time{now.Add(-time.Second), now.Add(MaxLease)} {
		if _, err := VerifyCurrent(body, expected, when); err == nil {
			t.Fatal("future/expired publication accepted")
		}
	}
	expected.MinimumSequence = 2
	if _, err := VerifyCurrent(body, expected, now); err == nil {
		t.Fatal("rolled-back publication accepted")
	}
	expected.MinimumSequence = 0
	p.Approval.Clusters[0].TrustDomain = "forged.mesh"
	body, _ = Encode(p)
	if _, err := DecodePublication(body); err == nil {
		t.Fatal("inner approval digest mismatch accepted")
	}
	p.State = "withdrawn"
	p.Reason = "SourceDeleted"
	p.Approval = nil
	p.ApprovalDigest = ""
	p.ValidUntil = Stamp(now)
	body, _ = Encode(p)
	if _, err := DecodePublication(body); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCurrent(body, expected, now); err == nil {
		t.Fatal("tombstone treated as trust")
	}
}

func TestJSONDepthBound(t *testing.T) {
	for _, depth := range []int{MaxJSONDepth - 1, MaxJSONDepth} {
		body := []byte(strings.Repeat("[", depth) + "0" + strings.Repeat("]", depth))
		var result any
		err := decode(body, &result)
		if depth < MaxJSONDepth {
			if err != nil {
				t.Fatalf("bounded JSON rejected: %v", err)
			}
		} else if err == nil || !strings.Contains(err.Error(), "nesting") {
			t.Fatalf("deep JSON must be rejected at scanner boundary: %v", err)
		}
	}
}

func approvalWithLargeIssuerCN(t *testing.T, commonNameLen int, unwrapPEM bool) (Approval, []string, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	root := makeCA(t, nil, now, nil)
	issuer := makeCA(t, root, now, func(cert *x509.Certificate) {
		cert.Subject.CommonName = strings.Repeat("a", commonNameLen)
	})
	issuerPEM := issuer.pem
	if unwrapPEM {
		lines := strings.Split(strings.TrimSpace(issuerPEM), "\n")
		issuerPEM = lines[0] + "\n" + strings.Join(lines[1:len(lines)-1], "") + "\n" + lines[len(lines)-1] + "\n"
	}
	a := Approval{
		SchemaVersion: SchemaVersion,
		Generation:    1,
		ExpiresAt:     Stamp(now.Add(time.Hour)),
		Roots:         []Root{{CertificatePEM: root.pem, SHA256: SHA(root.cert.Raw)}},
		Clusters: []Cluster{{
			ClusterID:   "cmtc-a",
			TrustDomain: "cmtc-a.mesh",
			Issuers: []Issuer{{
				CertificatePEM: issuerPEM,
				SPKISHA256:     SHA(issuer.cert.RawSubjectPublicKeyInfo),
				RootSHA256:     SHA(root.cert.Raw),
			}},
		}},
	}
	return a, []string{SHA(root.cert.Raw)}, now
}

func largestCanonicalApprovalUnderLimit(t *testing.T) (Approval, []string, time.Time, *Validated, int) {
	t.Helper()
	low, high := 40_000, 50_000
	bestLength, bestCN := 0, 0
	var best Approval
	var bestPins []string
	var bestNow time.Time
	var bestValidated *Validated
	for low <= high {
		mid := low + (high-low)/2
		a, pins, now := approvalWithLargeIssuerCN(t, mid, true)
		input := encodeApproval(t, a)
		validated, err := Validate(input, pins, "cmtc-a", now)
		if err == nil && len(input) <= MaxBytes {
			canonical, e := json.Marshal(validated.Approval)
			if e != nil {
				t.Fatal(e)
			}
			if len(canonical) <= MaxBytes {
				best, bestPins, bestNow, bestValidated = a, pins, now, validated
				bestLength, bestCN = len(canonical), mid
				low = mid + 1
				continue
			}
		}
		high = mid - 1
	}
	if bestValidated == nil || bestLength < MaxBytes-2048 {
		t.Fatalf("failed to construct valid near-limit approval: canonical bytes=%d", bestLength)
	}
	return best, bestPins, bestNow, bestValidated, bestCN
}

func publicationFor(valid *Validated, now time.Time) Publication {
	return Publication{
		SchemaVersion:          SchemaVersion,
		Sequence:               1,
		State:                  "published",
		Reason:                 "Validated",
		ProducerCluster:        "cmtc-a",
		OutputUID:              "output-v1",
		ExpectedSourceUID:      "source-v1",
		Source:                 Source{Namespace: "cmtc-system", Name: "approval", UID: "source-v1", ResourceVersion: "123", Generation: valid.Approval.Generation},
		AcceptedGeneration:     valid.Approval.Generation,
		AcceptedSourceUID:      "source-v1",
		AcceptedApprovalDigest: valid.Digest,
		Approval:               &valid.Approval,
		ApprovalDigest:         valid.Digest,
		PublishedAt:            Stamp(now),
		ValidUntil:             Stamp(now.Add(MaxLease)),
	}
}

func TestNearLimitApprovalEnvelopeRoundTripsAndCanonicalOverflowRejects(t *testing.T) {
	_, pins, now, valid, commonNameLen := largestCanonicalApprovalUnderLimit(t)
	approvalJSON, err := json.Marshal(valid.Approval)
	if err != nil {
		t.Fatal(err)
	}
	if len(approvalJSON) > MaxBytes || len(approvalJSON) < MaxBytes-2048 {
		t.Fatalf("canonical approval not near configured limit: %d", len(approvalJSON))
	}
	encoded, err := Encode(publicationFor(valid, now))
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) <= MaxBytes || len(encoded) > MaxPublicationBytes {
		t.Fatalf("want bounded envelope larger than old 64 KiB decoder limit; bytes=%d", len(encoded))
	}
	if _, err := DecodePublication(encoded); err != nil {
		t.Fatalf("publication rejected its own encoded near-limit approval: %v", err)
	}
	expected := Expected{OutputUID: "output-v1", SourceUID: "source-v1", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, MinimumSequence: 1, RootPins: pins}
	if _, err := VerifyCurrent(encoded, expected, now); err != nil {
		t.Fatalf("consumer rejected a publication produced by Encode: %v", err)
	}

	// One longer unwrapped PEM is still below the raw input limit but expands
	// past the canonical approval budget when PEM line breaks are normalized.
	foundCanonicalOverflow := false
	for n := commonNameLen + 1; n <= commonNameLen+256; n += 16 {
		a, inputPins, inputNow := approvalWithLargeIssuerCN(t, n, true)
		input := encodeApproval(t, a)
		if len(input) >= MaxBytes {
			continue
		}
		_, err := Validate(input, inputPins, "cmtc-a", inputNow)
		if err != nil && strings.Contains(err.Error(), "canonical approval exceeds issuer-profile size limit") {
			foundCanonicalOverflow = true
			break
		}
	}
	if !foundCanonicalOverflow {
		t.Fatal("raw-under-limit unwrapped PEM did not exercise canonical expansion bound")
	}
}

func TestPublicationEnvelopeLimitAndWithdrawnFloorShape(t *testing.T) {
	a, pins, now := approvalFixture(t)
	valid, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge := publicationFor(valid, now)
	tooLarge.Reason = strings.Repeat("x", MaxPublicationBytes)
	if _, err := Encode(tooLarge); err == nil {
		t.Fatal("Encode emitted an envelope above MaxPublicationBytes")
	}
	tooLarge.Digest = ""
	unsigned, err := json.Marshal(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	tooLarge.Digest = SHA(unsigned)
	overLimit, err := json.Marshal(tooLarge)
	if err != nil {
		t.Fatal(err)
	}
	if len(overLimit) <= MaxPublicationBytes {
		t.Fatal("oversize decoder fixture did not cross the configured envelope bound")
	}
	if _, err := DecodePublication(overLimit); err == nil {
		t.Fatal("DecodePublication accepted an oversized digest-correct envelope")
	}

	for _, tc := range []struct {
		name       string
		generation uint64
		sourceUID  string
		digest     string
		wantErr    bool
		liveLease  bool
	}{
		{name: "empty floor before first acceptance"},
		{name: "complete accepted floor", generation: 1, sourceUID: "source-v1", digest: valid.Digest},
		{name: "generation without tuple", generation: 1, digest: valid.Digest, wantErr: true},
		{name: "uid without generation", sourceUID: "source-v1", wantErr: true},
		{name: "digest without generation", digest: valid.Digest, wantErr: true},
		{name: "withdrawal with live lease", liveLease: true, wantErr: true},
		{name: "bad digest", generation: 1, sourceUID: "source-v1", digest: "bad", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := publicationFor(valid, now)
			p.State = "withdrawn"
			p.Reason = "SourceDeleted"
			p.Approval = nil
			p.ApprovalDigest = ""
			p.ValidUntil = p.PublishedAt
			if tc.liveLease {
				p.ValidUntil = Stamp(now.Add(MaxLease))
			}
			p.AcceptedGeneration = tc.generation
			p.AcceptedSourceUID = tc.sourceUID
			p.AcceptedApprovalDigest = tc.digest
			body, err := Encode(p)
			if err != nil {
				t.Fatal(err)
			}
			_, err = DecodePublication(body)
			if tc.wantErr && err == nil {
				t.Fatal("partial tombstone rollback floor accepted")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("valid tombstone rejected: %v", err)
			}
		})
	}
}
