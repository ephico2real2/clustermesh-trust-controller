package trustprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

var planNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

type planCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// planCert issues a certificate the way cert-manager and SPIRE do for the mesh: path length unset for the root and the
// intermediate, zero for a SPIRE CA, and the trust domain URI on a SPIRE CA and an SVID.
func planCert(t *testing.T, cn string, parent *planCA, notBefore, notAfter time.Time, isCA bool, pathLen int, uri string) *planCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter, BasicConstraintsValid: true}
	if isCA {
		tmpl.IsCA, tmpl.KeyUsage = true, x509.KeyUsageCertSign|x509.KeyUsageCRLSign
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = pathLen, pathLen == 0
	} else {
		tmpl.KeyUsage, tmpl.ExtKeyUsage = x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	if uri != "" {
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	signer, signingKey := tmpl, key
	if parent != nil {
		signer, signingKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &planCA{cert: cert, key: key}
}

func (c *planCA) pem() string { return canonical(c.cert) }

type mesh struct {
	root          *planCA
	intermediates map[string]*planCA
}

func newMesh(t *testing.T) *mesh {
	t.Helper()
	m := &mesh{root: planCert(t, "cmtc mesh root CA", nil, planNow.Add(-24*time.Hour), planNow.AddDate(10, 0, 0), true, -1, ""), intermediates: map[string]*planCA{}}
	for _, c := range []string{"cmtc-a", "cmtc-b"} {
		m.intermediates[c] = m.intermediate(t, c, planNow.Add(-300*24*time.Hour), planNow.Add(60*24*time.Hour))
	}
	return m
}

func (m *mesh) intermediate(t *testing.T, cluster string, notBefore, notAfter time.Time) *planCA {
	t.Helper()
	return planCert(t, IntermediateCommonName(cluster), m.root, notBefore, notAfter, true, -1, "")
}

func (m *mesh) rootPins() []string { return []string{SHA(m.root.cert.Raw)} }

func evidenceFor(t *testing.T, m *mesh, cluster string, intermediate *planCA, now time.Time) Evidence {
	t.Helper()
	issuer, _, err := SPIREIntermediateIssuer(cluster, intermediate.pem(), m.root.cert, now)
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{Issuer: &issuer, SPIRECAMaxDuration: 48 * time.Hour}
}

func planInput(t *testing.T, m *mesh, now time.Time, previous *Approval, ledger []IssuerRecord, evidence map[string]Evidence) PlanInput {
	t.Helper()
	generation := uint64(6)
	if previous != nil {
		generation = previous.Generation
	}
	return PlanInput{Now: now, LocalCluster: "cmtc-a", RootPins: m.rootPins(), RootPEM: m.root.pem(),
		Clusters: []ClusterIdentity{{"cmtc-a", "cmtc-a.mesh.example"}, {"cmtc-b", "cmtc-b.mesh.example"}},
		Evidence: evidence, Previous: previous, Generation: generation, Ledger: ledger,
		Horizon: MaxHorizon, RenewBefore: 7 * 24 * time.Hour, RetirementMargin: time.Hour,
		MeshTrusts: func(string, string) bool { return true }}
}

func mustPlan(t *testing.T, in PlanInput) Plan {
	t.Helper()
	p, err := PlanApproval(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func validated(t *testing.T, m *mesh, a *Approval, now time.Time) *Validated {
	t.Helper()
	body, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Validate(body, m.rootPins(), "cmtc-a", now)
	if err != nil {
		t.Fatalf("planned approval is refused by the producer's validation: %v", err)
	}
	return v
}

func issuerKeys(a *Approval, cluster string) []string {
	for _, c := range a.Clusters {
		if c.ClusterID == cluster {
			var keys []string
			for _, i := range c.Issuers {
				keys = append(keys, i.SPKISHA256)
			}
			return keys
		}
	}
	return nil
}

func spki(c *planCA) string { return SHA(c.cert.RawSubjectPublicKeyInfo) }

func holdReasons(p Plan) string {
	var reasons []string
	for _, h := range p.Holds {
		reasons = append(reasons, h.Cluster+":"+h.Reason)
	}
	return strings.Join(reasons, ",")
}

// ztunnelAccepts models ztunnel's verifier for a signsSPIRECA pin (src/tls/domain_anchors.rs:556-577, 608): the SVID
// path is pin -> exactly one SPIRE CA -> SVID, and exactly one pin of the trust domain may accept it.
func ztunnelAccepts(t *testing.T, a *Approval, domain string, spireCA, svid *planCA, now time.Time) bool {
	t.Helper()
	matched := 0
	for _, c := range a.Clusters {
		if c.TrustDomain != domain {
			continue
		}
		for _, i := range c.Issuers {
			pin, err := oneCertificate(i.CertificatePEM)
			if err != nil {
				t.Fatal(err)
			}
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(pin)
			intermediates.AddCert(spireCA.cert)
			chains, err := svid.cert.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
			if err == nil && len(chains) == 1 && len(chains[0]) == 3 {
				matched++
			}
		}
	}
	return matched == 1
}

// The failure this change removes: cert-manager renews the SPIRE intermediate with a new key (rotationPolicy Always),
// SPIRE keeps its active CA under the old key until its next activation, and an approval that names one intermediate
// refuses one of the two. The arbiter's overlap accepts both until no SPIRE CA under the old key can be live.
func TestIntermediateKeyRotationNeedsOverlap(t *testing.T) {
	m := newMesh(t)
	domain := "cmtc-a.mesh.example"
	oldKey := m.intermediates["cmtc-a"]
	bootstrap := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", oldKey, planNow), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)}))
	if bootstrap.Next == nil || bootstrap.Reason != ReasonBootstrap || bootstrap.Next.Generation != 7 {
		t.Fatalf("bootstrap: %+v holds %s", bootstrap, holdReasons(bootstrap))
	}
	first := validated(t, m, bootstrap.Next, planNow).Approval
	// SPIRE's active CA, minted under the old key just before cert-manager's renewal, valid for the policy's 48 hours.
	oldCA := planCert(t, "cmtc-a SPIRE CA", oldKey, planNow.Add(-time.Minute), planNow.Add(48*time.Hour-time.Minute), true, 0, "spiffe://"+domain)
	oldSVID := planCert(t, "workload", oldCA, planNow, planNow.Add(time.Hour), false, 0, "spiffe://"+domain+"/ns/app/sa/api")

	// cert-manager renews: a new key. SPIRE prepares its next CA under it and activates it later.
	switched := planNow.Add(time.Minute)
	newKey := m.intermediate(t, "cmtc-a", switched, switched.AddDate(1, 0, 0))
	newCA := planCert(t, "cmtc-a SPIRE CA", newKey, switched.Add(12*time.Hour), switched.Add(36*time.Hour), true, 0, "spiffe://"+domain)
	newSVID := planCert(t, "workload", newCA, switched.Add(20*time.Hour), switched.Add(21*time.Hour), false, 0, "spiffe://"+domain+"/ns/app/sa/api")
	activation := switched.Add(20 * time.Hour)

	// Reproduced: the approval that pins only the old key refuses every SVID once SPIRE activates under the new key
	// (the shape of the 2026-10-25 outage), and an approval that follows cert-manager without overlap refuses SPIRE's
	// still-active CA (the 10:33Z curl 56 of 2026-10-27).
	if !ztunnelAccepts(t, &first, domain, oldCA, oldSVID, planNow) || ztunnelAccepts(t, &first, domain, newCA, newSVID, activation) {
		t.Fatal("the single-key approval must accept the old chain and refuse the new one")
	}
	naive := first
	naive.Clusters = append([]Cluster(nil), first.Clusters...)
	naive.Clusters[0] = Cluster{ClusterID: "cmtc-a", TrustDomain: domain, Issuers: []Issuer{*evidenceFor(t, m, "cmtc-a", newKey, switched).Issuer}}
	if ztunnelAccepts(t, &naive, domain, oldCA, oldSVID, switched) {
		t.Fatal("the new-key-only approval must refuse SPIRE's active CA under the old key")
	}
	if err := CheckSuccession(&first, &naive, bootstrap.Ledger, switched, time.Hour, func(string, string) bool { return true }); err == nil || !strings.Contains(err.Error(), "NoOverlap") {
		t.Fatalf("a successor without the live predecessor must be refused: %v", err)
	}

	// Fixed: the arbiter adds the new key and keeps the old one.
	rotation := mustPlan(t, planInput(t, m, switched, &first, bootstrap.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, switched), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], switched)}))
	if rotation.Next == nil || rotation.Reason != ReasonIssuerAdded || len(issuerKeys(rotation.Next, "cmtc-a")) != 2 || rotation.Next.Generation != 8 {
		t.Fatalf("rotation plan: %+v holds %s", rotation.Next, holdReasons(rotation))
	}
	if err := CheckSuccession(&first, rotation.Next, rotation.Ledger, switched, time.Hour, func(string, string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	overlap := validated(t, m, rotation.Next, switched).Approval
	if !ztunnelAccepts(t, &overlap, domain, oldCA, oldSVID, switched) || !ztunnelAccepts(t, &overlap, domain, newCA, newSVID, activation) {
		t.Fatal("the overlap must accept SPIRE's CA under either key")
	}

	// Retirement waits for the SPIRE CA bound and for every node of every cluster.
	retireAt := switched.Add(48*time.Hour + time.Hour)
	if !oldCA.cert.NotAfter.Before(retireAt) {
		t.Fatalf("a SPIRE CA under the old key outlives its retirement: %s >= %s", oldCA.cert.NotAfter, retireAt)
	}
	early := mustPlan(t, planInput(t, m, retireAt.Add(-time.Second), &overlap, rotation.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, retireAt), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], retireAt)}))
	if early.Next != nil || !strings.Contains(holdReasons(early), "cmtc-a:"+HoldRetirementWaiting) {
		t.Fatalf("retired before the bound: %+v %s", early.Next, holdReasons(early))
	}
	waiting := planInput(t, m, retireAt, &overlap, rotation.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, retireAt), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], retireAt)})
	waiting.MeshTrusts = func(cluster, key string) bool { return !(cluster == "cmtc-a" && key == spki(newKey)) }
	if p := mustPlan(t, waiting); p.Next != nil {
		t.Fatal("retired while a node does not report trusting the successor")
	}
	retire := mustPlan(t, planInput(t, m, retireAt, &overlap, rotation.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, retireAt), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], retireAt)}))
	if retire.Next == nil || retire.Reason != ReasonIssuerRetired || strings.Join(issuerKeys(retire.Next, "cmtc-a"), ",") != spki(newKey) {
		t.Fatalf("retirement plan: %+v %s", retire.Next, holdReasons(retire))
	}
	if err := CheckSuccession(&overlap, retire.Next, retire.Ledger, retireAt, time.Hour, func(string, string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	// The record of the retired key stays while the published approval still holds the key, and goes after.
	final := validated(t, m, retire.Next, retireAt).Approval
	after := mustPlan(t, planInput(t, m, retireAt.Add(time.Minute), &final, retire.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, retireAt), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], retireAt)}))
	if after.Next != nil || len(retire.Ledger) != 3 || len(after.Ledger) != 2 {
		t.Fatalf("ledger after retirement: %d then %d records, next %+v", len(retire.Ledger), len(after.Ledger), after.Next)
	}
}

func TestPeerEvidenceAbsentKeepsTheLastApproval(t *testing.T) {
	m := newMesh(t)
	both := map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", m.intermediates["cmtc-a"], planNow), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)}
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, both))
	previous := validated(t, m, first.Next, planNow).Approval
	expiry, _ := time.Parse(time.RFC3339, previous.ExpiresAt)

	// Before the first approval, every cluster's evidence is required.
	if p := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": both["cmtc-a"]})); p.Next != nil {
		t.Fatal("bootstrapped without the peer's evidence")
	}
	peerDown := map[string]Evidence{"cmtc-a": both["cmtc-a"], "cmtc-b": {Reason: HoldEvidenceUnavailable, Message: "peer API: connection refused"}}
	due := expiry.Add(-6 * 24 * time.Hour)
	p := mustPlan(t, planInput(t, m, due, &previous, first.Ledger, peerDown))
	if p.Next != nil || !strings.Contains(holdReasons(p), ":"+HoldRenewalWaits) || !strings.Contains(holdReasons(p), "cmtc-b:"+HoldEvidenceUnavailable) {
		t.Fatalf("renewed on the peer's stale material: %+v %s", p.Next, holdReasons(p))
	}
	// A local rotation still goes out, with the peer's last issuers and no later expiry than the last approval.
	newKey := m.intermediate(t, "cmtc-a", due, due.AddDate(1, 0, 0))
	peerDown["cmtc-a"] = evidenceFor(t, m, "cmtc-a", newKey, due)
	p = mustPlan(t, planInput(t, m, due, &previous, first.Ledger, peerDown))
	if p.Next == nil || p.Reason != ReasonIssuerAdded || p.Next.ExpiresAt != previous.ExpiresAt ||
		strings.Join(issuerKeys(p.Next, "cmtc-b"), ",") != strings.Join(issuerKeys(&previous, "cmtc-b"), ",") {
		t.Fatalf("local rotation with the peer down: %+v", p.Next)
	}
	// With fresh peer evidence the renewal extends the expiry.
	renewed := mustPlan(t, planInput(t, m, due, &previous, first.Ledger, both))
	if renewed.Next == nil || renewed.Reason != ReasonRenewal || renewed.Next.ExpiresAt <= previous.ExpiresAt {
		t.Fatalf("renewal: %+v %s", renewed.Next, holdReasons(renewed))
	}
}

func TestReplacedCertificateIsRefused(t *testing.T) {
	m := newMesh(t)
	both := map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", m.intermediates["cmtc-a"], planNow), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)}
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, both))
	previous := validated(t, m, first.Next, planNow).Approval
	// The Certificate was deleted and recreated: a new UID and a new key. The arbiter never adopts its issuer, even
	// when the evidence carries one.
	replaced := evidenceFor(t, m, "cmtc-a", m.intermediate(t, "cmtc-a", planNow, planNow.AddDate(1, 0, 0)), planNow)
	replaced.Refused, replaced.Reason = true, "CertificateUIDMismatch"
	p := mustPlan(t, planInput(t, m, planNow.Add(time.Hour), &previous, first.Ledger, map[string]Evidence{"cmtc-a": replaced, "cmtc-b": both["cmtc-b"]}))
	if p.Next != nil || !strings.Contains(holdReasons(p), "cmtc-a:"+HoldEvidenceRefused) {
		t.Fatalf("adopted a replaced Certificate: %+v %s", p.Next, holdReasons(p))
	}
	if _, ok := p.Current["cmtc-a"]; ok {
		t.Fatal("a refused issuer is recorded as current")
	}
}

func TestThirdKeyWaitsForARetirement(t *testing.T) {
	m := newMesh(t)
	k1, k2, k3 := m.intermediates["cmtc-a"], m.intermediate(t, "cmtc-a", planNow, planNow.AddDate(1, 0, 0)), m.intermediate(t, "cmtc-a", planNow.Add(time.Hour), planNow.AddDate(1, 0, 0))
	b := evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", k1, planNow), "cmtc-b": b}))
	one := validated(t, m, first.Next, planNow).Approval
	second := mustPlan(t, planInput(t, m, planNow, &one, first.Ledger, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", k2, planNow), "cmtc-b": b}))
	two := validated(t, m, second.Next, planNow).Approval
	p := mustPlan(t, planInput(t, m, planNow.Add(time.Hour), &two, second.Ledger, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", k3, planNow.Add(time.Hour)), "cmtc-b": b}))
	if p.Next != nil || !strings.Contains(holdReasons(p), "cmtc-a:"+HoldOverlapFull) {
		t.Fatalf("a third key went in or was not held: %+v %s", p.Next, holdReasons(p))
	}
	// Once the oldest key may retire, it leaves and the third key enters in the same generation. The nodes trust only
	// the published keys: the first key retires on their trust in its successor, the second key, not in the third,
	// which no node can trust before it is published (otherwise this would deadlock).
	later := planNow.Add(50 * time.Hour)
	in := planInput(t, m, later, &two, p.Ledger, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", k3, later), "cmtc-b": b})
	published := strings.Join(issuerKeys(&two, "cmtc-a"), ",")
	in.MeshTrusts = func(cluster, key string) bool { return cluster != "cmtc-a" || strings.Contains(published, key) }
	p = mustPlan(t, in)
	if p.Next == nil {
		t.Fatalf("no plan after the bound: %s", holdReasons(p))
	}
	if keys := strings.Join(issuerKeys(p.Next, "cmtc-a"), ","); strings.Contains(keys, spki(k1)) || !strings.Contains(keys, spki(k3)) || !strings.Contains(keys, spki(k2)) {
		t.Fatalf("after the bound: %s %s", keys, holdReasons(p))
	}
	if err := CheckSuccession(&two, p.Next, p.Ledger, later, time.Hour, in.MeshTrusts); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalExpiryMargins(t *testing.T) {
	m := newMesh(t)
	both := map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", m.intermediates["cmtc-a"], planNow), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)}
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, both))
	if first.Next.ExpiresAt != Stamp(planNow.Add(MaxHorizon)) {
		t.Fatalf("bootstrap expiry %s, want now + %s", first.Next.ExpiresAt, MaxHorizon)
	}
	previous := validated(t, m, first.Next, planNow).Approval
	expiry := planNow.Add(MaxHorizon)
	if p := mustPlan(t, planInput(t, m, expiry.Add(-7*24*time.Hour-time.Second), &previous, first.Ledger, both)); p.Next != nil {
		t.Fatal("renewed before renewBefore")
	}
	at := expiry.Add(-7 * 24 * time.Hour)
	if p := mustPlan(t, planInput(t, m, at, &previous, first.Ledger, both)); p.Next == nil || p.Reason != ReasonRenewal {
		t.Fatal("not renewed at renewBefore")
	}
	// The expiry never passes an issuer certificate's own end.
	short := m.intermediate(t, "cmtc-b", planNow.Add(-time.Hour), planNow.Add(10*24*time.Hour))
	capped := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": both["cmtc-a"], "cmtc-b": evidenceFor(t, m, "cmtc-b", short, planNow)}))
	if capped.Next.ExpiresAt != Stamp(short.cert.NotAfter) {
		t.Fatalf("expiry %s passes the issuer's end %s", capped.Next.ExpiresAt, short.cert.NotAfter)
	}
	// An approval that would end within the retirement margin is not written.
	ending := m.intermediate(t, "cmtc-b", planNow.Add(-time.Hour), planNow.Add(30*time.Minute))
	if p := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": both["cmtc-a"], "cmtc-b": evidenceFor(t, m, "cmtc-b", ending, planNow)})); p.Next != nil {
		t.Fatalf("wrote an approval ending within the margin: %s", p.Next.ExpiresAt)
	}
	// A superseded issuer near its own end leaves without the retirement gates.
	oldB := m.intermediate(t, "cmtc-b", planNow.Add(-300*24*time.Hour), planNow.Add(2*time.Hour))
	firstOld := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": both["cmtc-a"], "cmtc-b": evidenceFor(t, m, "cmtc-b", oldB, planNow)}))
	withOld := firstOld.Next
	withOld.Clusters[1].Issuers = append(withOld.Clusters[1].Issuers, *both["cmtc-b"].Issuer)
	near := planNow.Add(90 * time.Minute)
	in := planInput(t, m, near, withOld, firstOld.Ledger, map[string]Evidence{"cmtc-a": both["cmtc-a"], "cmtc-b": both["cmtc-b"]})
	in.MeshTrusts = func(string, string) bool { return false }
	if p := mustPlan(t, in); p.Next == nil || p.Reason != ReasonIssuerExpired || strings.Contains(strings.Join(issuerKeys(p.Next, "cmtc-b"), ","), spki(oldB)) {
		t.Fatalf("expiring issuer kept: %+v %s", p.Next, holdReasons(p))
	}
	for name, change := range map[string]func(*PlanInput){
		"horizon over 29 days":         func(in *PlanInput) { in.Horizon = MaxHorizon + time.Second },
		"margin not under renewBefore": func(in *PlanInput) { in.RetirementMargin = in.RenewBefore },
		"renewBefore not under horizon": func(in *PlanInput) {
			in.RenewBefore = in.Horizon
		},
		"local cluster not configured": func(in *PlanInput) { in.LocalCluster = "cmtc-c" },
	} {
		in := planInput(t, m, planNow, nil, nil, both)
		change(&in)
		if _, err := PlanApproval(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRootChangeIsRefused(t *testing.T) {
	m := newMesh(t)
	both := map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", m.intermediates["cmtc-a"], planNow), "cmtc-b": evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)}
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, both))
	other := newMesh(t)
	in := planInput(t, other, planNow, first.Next, first.Ledger, map[string]Evidence{
		"cmtc-a": evidenceFor(t, other, "cmtc-a", other.intermediates["cmtc-a"], planNow), "cmtc-b": evidenceFor(t, other, "cmtc-b", other.intermediates["cmtc-b"], planNow)})
	in.RootPins = append(in.RootPins, m.rootPins()...)
	if p := mustPlan(t, in); p.Next != nil || holdReasons(p) != ":"+HoldRootChanged {
		t.Fatalf("root change: %+v %s", p.Next, holdReasons(p))
	}
	in.RootPins = m.rootPins()
	if _, err := PlanApproval(in); err == nil {
		t.Fatal("an unpinned mesh root was accepted")
	}
}

func TestSPIREIntermediateEvidenceRules(t *testing.T) {
	m := newMesh(t)
	good := m.intermediates["cmtc-a"]
	if _, _, err := SPIREIntermediateIssuer("cmtc-a", good.pem(), m.root.cert, planNow); err != nil {
		t.Fatal(err)
	}
	other := newMesh(t)
	for name, pem := range map[string]string{
		"another cluster's name":    m.intermediates["cmtc-b"].pem(),
		"not signed by the root":    other.intermediates["cmtc-a"].pem(),
		"path length zero":          planCert(t, IntermediateCommonName("cmtc-a"), m.root, planNow.Add(-time.Hour), planNow.AddDate(1, 0, 0), true, 0, "").pem(),
		"expired":                   m.intermediate(t, "cmtc-a", planNow.Add(-48*time.Hour), planNow.Add(-time.Hour)).pem(),
		"not a CA":                  planCert(t, IntermediateCommonName("cmtc-a"), m.root, planNow.Add(-time.Hour), planNow.AddDate(1, 0, 0), false, 0, "").pem(),
		"a SAN outside the profile": planCert(t, IntermediateCommonName("cmtc-a"), m.root, planNow.Add(-time.Hour), planNow.AddDate(1, 0, 0), true, -1, "spiffe://cmtc-a.mesh.example").pem(),
		"two certificates":          good.pem() + m.root.pem(),
	} {
		if _, _, err := SPIREIntermediateIssuer("cmtc-a", pem, m.root.cert, planNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseRoot(m.root.pem(), other.rootPins(), planNow); err == nil {
		t.Error("an unpinned root was accepted")
	}
	if _, err := ParseRoot(good.pem(), []string{SHA(good.cert.Raw)}, planNow); err == nil {
		t.Error("an intermediate was accepted as the root")
	}
}

// The SPIRE CA bound of a key is the largest approver-policy maxDuration seen while the key was current or superseded:
// a CA signed under the old key before the renewal lived under the bound of that time, so a bound lowered afterwards
// does not shorten the retirement.
func TestRetirementBoundKeepsTheLargestPolicyDuration(t *testing.T) {
	m := newMesh(t)
	oldKey, b := m.intermediates["cmtc-a"], evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], planNow)
	wide := evidenceFor(t, m, "cmtc-a", oldKey, planNow)
	wide.SPIRECAMaxDuration = 72 * time.Hour
	first := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": wide, "cmtc-b": b}))
	one := validated(t, m, first.Next, planNow).Approval
	switched := planNow.Add(time.Minute)
	narrow := evidenceFor(t, m, "cmtc-a", m.intermediate(t, "cmtc-a", switched, switched.AddDate(1, 0, 0)), switched)
	narrow.SPIRECAMaxDuration = 24 * time.Hour
	rotation := mustPlan(t, planInput(t, m, switched, &one, first.Ledger, map[string]Evidence{"cmtc-a": narrow, "cmtc-b": b}))
	if rotation.Next == nil || rotation.Reason != ReasonIssuerAdded {
		t.Fatalf("rotation: %+v %s", rotation.Next, holdReasons(rotation))
	}
	for _, r := range rotation.Ledger {
		if r.Cluster == "cmtc-a" && r.SPKISHA256 == spki(oldKey) {
			if at, ok := r.RetireAfter(time.Hour); !ok || !at.Equal(switched.Add(72*time.Hour+time.Hour)) {
				t.Fatalf("retirement bound %s %v, want the 72h bound seen while current", at, ok)
			}
			return
		}
	}
	t.Fatal("no record of the old key")
}
