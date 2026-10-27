package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var passNow = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

type passCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// passCert issues a CA the way cert-manager does for the mesh: no path length on the root and the intermediate.
func passCert(t *testing.T, cn string, parent *passCA, notBefore, notAfter time.Time) *passCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter,
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: -1}
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
	return &passCA{cert: cert, key: key}
}

func (c *passCA) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}))
}

func (c *passCA) spki() string { return trustprofile.SHA(c.cert.RawSubjectPublicKeyInfo) }

func passScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// passMesh is the fake API of both clusters: the local one, and the peer read through Peers.
type passMesh struct {
	t      *testing.T
	root   *passCA
	keys   map[string]*passCA
	uids   map[string]types.UID
	local  client.Client
	peer   client.Client
	output *corev1.ConfigMap
}

func (m *passMesh) clientOf(cluster string) client.Client {
	if cluster == "cmtc-a" {
		return m.local
	}
	return m.peer
}

func passOptions(m *passMesh) IssuerApprovalOptions {
	return IssuerApprovalOptions{Namespace: "cmtc-system", Slots: [2]string{"cmtc-issuer-approval-a", "cmtc-issuer-approval-b"}, Output: "cmtc-issuer-publication",
		RootConfigMap: "cmtc-mesh-root", CertManagerNamespace: "cert-manager", RootIssuer: "cmtc-mesh-root", SPIRENamespace: "cilium-spire", SPIREConfigMap: "spire-server",
		LocalCluster: "cmtc-a", RootPins: []string{trustprofile.SHA(m.root.cert.Raw)}, MinimumGeneration: 7,
		Clusters: []ApprovalCluster{
			{Name: "cmtc-a", TrustDomain: "cmtc-a.mesh.example", Certificate: "cmtc-a-spire-intermediate", CertificateUID: m.uids["cmtc-a"]},
			{Name: "cmtc-b", TrustDomain: "cmtc-b.mesh.example", Certificate: "cmtc-b-spire-intermediate", CertificateUID: m.uids["cmtc-b"]}},
		Horizon: trustprofile.MaxHorizon, RenewBefore: 7 * 24 * time.Hour, RetirementMargin: time.Hour, ReportMaxAge: DefaultReportMaxAge}
}

func unstructuredObject(gvk string, namespace, name string, uid types.UID, spec, status map[string]any) *unstructured.Unstructured {
	group, version, kind := "", "", ""
	parts := strings.Split(gvk, "/")
	if len(parts) == 3 {
		group, version, kind = parts[0], parts[1], parts[2]
	} else {
		version, kind = parts[0], parts[1]
	}
	u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	if status != nil {
		u.Object["status"] = status
	}
	u.SetAPIVersion(strings.TrimPrefix(group+"/"+version, "/"))
	u.SetKind(kind)
	u.SetNamespace(namespace)
	u.SetName(name)
	u.SetUID(uid)
	return u
}

func ready(kinds ...string) []any {
	var out []any
	for _, k := range kinds {
		out = append(out, map[string]any{"type": k, "status": "True"})
	}
	return out
}

// certificateObjects are cert-manager's public objects of one cluster's SPIRE intermediate at a revision.
func certificateObjects(m *passMesh, cluster string, revision int64, key *passCA) []client.Object {
	name := cluster + "-spire-intermediate"
	ref := map[string]any{"name": "cmtc-mesh-root", "kind": "ClusterIssuer", "group": "cert-manager.io"}
	cert := unstructuredObject("cert-manager.io/v1/Certificate", "cert-manager", name, m.uids[cluster],
		map[string]any{"isCA": true, "secretName": name, "issuerRef": ref},
		map[string]any{"revision": revision, "notAfter": trustprofile.Stamp(key.cert.NotAfter), "conditions": ready("Ready")})
	controller := true
	request := unstructuredObject("cert-manager.io/v1/CertificateRequest", "cert-manager", name+"-"+strconv.FormatInt(revision, 10), types.UID(name+"-request-"+strconv.FormatInt(revision, 10)),
		map[string]any{"issuerRef": ref},
		map[string]any{"conditions": ready("Approved", "Ready"), "certificate": base64.StdEncoding.EncodeToString([]byte(key.pem()))})
	request.SetAnnotations(map[string]string{"cert-manager.io/certificate-revision": strconv.FormatInt(revision, 10)})
	request.SetOwnerReferences([]metav1.OwnerReference{{APIVersion: "cert-manager.io/v1", Kind: "Certificate", Name: name, UID: m.uids[cluster], Controller: &controller}})
	return []client.Object{cert, request}
}

func newPassMesh(t *testing.T) *passMesh {
	t.Helper()
	m := &passMesh{t: t, root: passCert(t, "cmtc mesh root CA", nil, passNow.Add(-24*time.Hour), passNow.AddDate(10, 0, 0)), keys: map[string]*passCA{}, uids: map[string]types.UID{}}
	scheme := passScheme(t)
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		m.keys[cluster] = passCert(t, trustprofile.IntermediateCommonName(cluster), m.root, passNow.Add(-300*24*time.Hour), passNow.Add(60*24*time.Hour))
		m.uids[cluster] = types.UID(cluster + "-certificate-uid")
		name := cluster + "-spire-intermediate"
		objects := []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "cmtc-system", Name: "cmtc-mesh-root"}, Data: map[string]string{"ca.crt": m.root.pem()}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "cmtc-system", Name: "cmtc-issuer-publication", UID: types.UID(cluster + "-output"), Labels: map[string]string{trustprofile.OutputLabel: "true"}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "cilium-spire", Name: "spire-server"}, Data: map[string]string{"server.conf": "server {\n  ca_ttl = \"48h\"\n}\nUpstreamAuthority \"cert-manager\" {\n  plugin_data {\n    namespace = \"cilium-spire\"\n    issuer_name = \"" + name + "\"\n  }\n}\n"}},
			unstructuredObject("cert-manager.io/v1/ClusterIssuer", "", name, types.UID(name+"-issuer"), map[string]any{"ca": map[string]any{"secretName": name}}, nil),
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: cluster + "-control-plane"}},
			&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: cluster + "-worker"}},
		}
		objects = append(objects, certificateObjects(m, cluster, 1, m.keys[cluster])...)
		c := uidClient{fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&api.IssuerApproval{}).WithObjects(objects...).Build()}
		if cluster == "cmtc-a" {
			m.local = c
		} else {
			m.peer = c
		}
	}
	var out corev1.ConfigMap
	if err := m.local.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-publication"}, &out); err != nil {
		t.Fatal(err)
	}
	m.output = &out
	return m
}

// report writes or moves one node's report, as its node agent would.
func (m *passMesh) report(cluster, node string, at time.Time, pins api.PinsReport, ztunnel api.ZtunnelReport) {
	m.t.Helper()
	c, ctx := m.clientOf(cluster), context.Background()
	status := api.NodeTrustReportStatus{Cluster: cluster, ObservedAt: metav1.NewTime(at), Pins: pins, Ztunnel: ztunnel}
	var r api.NodeTrustReport
	err := c.Get(ctx, client.ObjectKey{Name: node}, &r)
	switch {
	case err == nil:
		r.Status = status
		err = c.Update(ctx, &r)
	default:
		err = c.Create(ctx, &api.NodeTrustReport{ObjectMeta: metav1.ObjectMeta{Name: node}, Status: status})
	}
	if err != nil {
		m.t.Fatal(err)
	}
}

// accept moves every node's report to accept the local publication's generation, trusting the keys the approval holds.
func (m *passMesh) accept(at time.Time, p *trustprofile.Publication) {
	m.t.Helper()
	root := p.Approval.Roots[0].SHA256
	var trusted []api.TrustedIssuer
	for _, c := range p.Approval.Clusters {
		for _, i := range c.Issuers {
			trusted = append(trusted, api.TrustedIssuer{TrustDomain: c.TrustDomain, SPKISHA256: i.SPKISHA256})
		}
	}
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		for _, node := range []string{cluster + "-control-plane", cluster + "-worker"} {
			m.report(cluster, node, at, api.PinsReport{State: api.PinsReadOnly, RootSHA256: []string{root}},
				api.ZtunnelReport{State: api.ZtunnelAccepted, Observation: "Validated", AcceptedGeneration: int64(p.AcceptedGeneration), ApprovalDigest: p.AcceptedApprovalDigest, LoadedRootSHA256: []string{root}, TrustedIssuers: trusted})
		}
	}
}

// heartbeat moves every report's ObservedAt without changing its observation.
func (m *passMesh) heartbeat(at time.Time) {
	m.t.Helper()
	ctx := context.Background()
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		var list api.NodeTrustReportList
		if err := m.clientOf(cluster).List(ctx, &list); err != nil {
			m.t.Fatal(err)
		}
		for i := range list.Items {
			list.Items[i].Status.ObservedAt = metav1.NewTime(at)
			if err := m.clientOf(cluster).Update(ctx, &list.Items[i]); err != nil {
				m.t.Fatal(err)
			}
		}
	}
}

// mirrorPeerPublication gives the peer the publication its own producer would hold: the same accepted generation.
func (m *passMesh) mirrorPeerPublication() {
	m.t.Helper()
	ctx := context.Background()
	var local, peer corev1.ConfigMap
	key := client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-publication"}
	if err := m.local.Get(ctx, key, &local); err != nil {
		m.t.Fatal(err)
	}
	if err := m.peer.Get(ctx, key, &peer); err != nil {
		m.t.Fatal(err)
	}
	peer.Data = local.Data
	if err := m.peer.Update(ctx, &peer); err != nil {
		m.t.Fatal(err)
	}
}

func (m *passMesh) publication() *trustprofile.Publication {
	m.t.Helper()
	_, p := readProfile(m.t, m.local, client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-publication"})
	return p
}

func (m *passMesh) slot(name string) *trustprofile.Approval {
	m.t.Helper()
	var cm corev1.ConfigMap
	err := m.local.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: name}, &cm)
	if err != nil {
		return nil
	}
	a, err := trustprofile.DecodeApproval([]byte(cm.Data[trustprofile.ApprovalKey]))
	if err != nil {
		m.t.Fatal(err)
	}
	return a
}

func issuersOf(a *trustprofile.Approval, cluster string) []string {
	var keys []string
	for _, c := range a.Clusters {
		if c.ClusterID == cluster {
			for _, i := range c.Issuers {
				keys = append(keys, i.SPKISHA256)
			}
		}
	}
	return keys
}

// uidClient gives every created object a UID, as the API server does and the fake client does not.
type uidClient struct{ client.Client }

func (c uidClient) Create(ctx context.Context, o client.Object, opts ...client.CreateOption) error {
	if o.GetUID() == "" {
		o.SetUID(types.UID(uuid.NewString()))
	}
	return c.Client.Create(ctx, o, opts...)
}

type failingReader struct{ client.Reader }

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("peer API: connection refused")
}
func (failingReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return errors.New("peer API: connection refused")
}

func newArbiter(t *testing.T, m *passMesh, now *time.Time) (*IssuerApprovalReconciler, *IssuerProfileReconciler) {
	t.Helper()
	arbiterMetrics, err := trustprofile.NewArbiterMetrics(prometheus.NewRegistry(), "cmtc-a")
	if err != nil {
		t.Fatal(err)
	}
	producerMetrics, err := trustprofile.NewMetrics(prometheus.NewRegistry(), "cmtc-a")
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return *now }
	arbiter := &IssuerApprovalReconciler{Client: m.local, Reader: m.local, Cache: m.local, Peers: map[string]client.Reader{"cmtc-b": m.peer}, Options: passOptions(m), Metrics: arbiterMetrics, Now: clock}
	producer := &IssuerProfileReconciler{Client: m.local, Reader: m.local, Follow: arbiter.FollowedSource, Metrics: producerMetrics, Now: clock,
		Options: IssuerProfileOptions{Output: client.ObjectKeyFromObject(m.output), OutputUID: m.output.UID, MinimumGeneration: 7, RootPins: arbiter.Options.RootPins, LocalCluster: "cmtc-a"}}
	return arbiter, producer
}

func pass(t *testing.T, r *IssuerApprovalReconciler) api.IssuerApprovalStatus {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatalf("arbiter pass: %v", err)
	}
	var record api.IssuerApproval
	if err := r.Reader.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: api.IssuerApprovalName}, &record); err != nil {
		t.Fatal(err)
	}
	return record.Status
}

func blockedReason(s api.IssuerApprovalStatus) string {
	if c := meta.FindStatusCondition(s.Conditions, ConditionBlocked); c != nil && c.Status == metav1.ConditionTrue {
		return c.Reason
	}
	return ""
}

func describe(s api.IssuerApprovalStatus) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// One arbiter lifecycle against fake APIs of both clusters: bootstrap only when every node of every cluster reports
// fresh; the producer publishes the slot the arbiter names; a renewed intermediate enters as an overlap, the predecessor
// slot goes once every local node accepts the new generation, and the old key retires after its SPIRE CA bound; a peer
// that is down blocks every write; a restarted arbiter resumes from the objects; a slot whose record was lost is removed.
func TestIssuerApprovalArbiterLifecycle(t *testing.T) {
	m := newPassMesh(t)
	now := passNow
	arbiter, producer := newArbiter(t, m, &now)

	// No node reports: nothing is written.
	if s := pass(t, arbiter); s.Phase != api.ApprovalBlocked || blockedReason(s) != BlockMeshNotConverged || s.Pending != nil || m.slot("cmtc-issuer-approval-a") != nil {
		t.Fatalf("without reports: %s", describe(s))
	}
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		for _, node := range []string{cluster + "-control-plane", cluster + "-worker"} {
			m.report(cluster, node, now, api.PinsReport{State: api.PinsReadOnly, RootSHA256: arbiter.Options.RootPins}, api.ZtunnelReport{State: api.ZtunnelAbsent})
		}
	}
	// A report counts as fresh only once this process saw its heartbeat move.
	if s := pass(t, arbiter); blockedReason(s) != BlockMeshNotConverged {
		t.Fatalf("first sighting counted as fresh: %s", describe(s))
	}
	now = now.Add(30 * time.Second)
	m.heartbeat(now)
	s := pass(t, arbiter)
	if s.Phase != api.ApprovalPublishing || s.Pending == nil || s.Pending.Slot != "cmtc-issuer-approval-a" || s.Pending.Generation != 7 || s.Pending.Reason != trustprofile.ReasonBootstrap {
		t.Fatalf("bootstrap: %s", describe(s))
	}
	if a := m.slot("cmtc-issuer-approval-a"); a == nil || a.Generation != 7 || len(issuersOf(a, "cmtc-a")) != 1 || len(issuersOf(a, "cmtc-b")) != 1 {
		t.Fatalf("bootstrap slot: %+v", a)
	}
	// The producer follows the pending slot; the arbiter then promotes it.
	now = now.Add(time.Second)
	reconcileProfile(t, producer)
	p := m.publication()
	if p.State != "published" || p.AcceptedGeneration != 7 || p.Source.Name != "cmtc-issuer-approval-a" {
		t.Fatalf("publication: %+v", p)
	}
	m.mirrorPeerPublication()
	if s := pass(t, arbiter); s.Phase != api.ApprovalDistributing || s.Pending != nil || s.Current == nil || s.Current.Generation != 7 || s.Current.Reason != trustprofile.ReasonBootstrap {
		t.Fatalf("promotion: %s", describe(s))
	}
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	if s := pass(t, arbiter); s.Phase != api.ApprovalConverged || blockedReason(s) != "" {
		t.Fatalf("converged: %s", describe(s))
	}

	// cert-manager renews cmtc-a's intermediate with a new key (rotationPolicy Always): the arbiter adds it and keeps
	// the old one, in the free slot.
	switched := now.Add(time.Minute)
	now = switched
	newKey := passCert(t, trustprofile.IntermediateCommonName("cmtc-a"), m.root, switched.Truncate(time.Second), switched.Truncate(time.Second).AddDate(1, 0, 0))
	for _, o := range certificateObjects(m, "cmtc-a", 2, newKey) {
		if o.GetObjectKind().GroupVersionKind().Kind == "Certificate" {
			current := object(certificateGVK)
			if err := m.local.Get(context.Background(), client.ObjectKeyFromObject(o), current); err != nil {
				t.Fatal(err)
			}
			current.Object["status"] = o.(*unstructured.Unstructured).Object["status"]
			if err := m.local.Update(context.Background(), current); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := m.local.Create(context.Background(), o); err != nil {
			t.Fatal(err)
		}
	}
	m.heartbeat(now)
	s = pass(t, arbiter)
	if s.Pending == nil || s.Pending.Slot != "cmtc-issuer-approval-b" || s.Pending.Generation != 8 || s.Pending.Reason != trustprofile.ReasonIssuerAdded {
		t.Fatalf("rotation: %s", describe(s))
	}
	overlap := m.slot("cmtc-issuer-approval-b")
	if keys := issuersOf(overlap, "cmtc-a"); len(keys) != 2 || !strings.Contains(strings.Join(keys, ","), newKey.spki()) || !strings.Contains(strings.Join(keys, ","), m.keys["cmtc-a"].spki()) {
		t.Fatalf("overlap keys: %v", keys)
	}
	now = now.Add(time.Second)
	reconcileProfile(t, producer)
	p = m.publication()
	if p.AcceptedGeneration != 8 {
		t.Fatalf("publication after rotation: %+v", p)
	}
	m.mirrorPeerPublication()
	// Promoted; the old slot stays while a local node still reads generation 7.
	if s := pass(t, arbiter); s.Current == nil || s.Current.Generation != 8 || m.slot("cmtc-issuer-approval-a") == nil || s.Phase != api.ApprovalDistributing {
		t.Fatalf("after rotation publish: %s", describe(s))
	}
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	if s := pass(t, arbiter); m.slot("cmtc-issuer-approval-a") != nil {
		t.Fatalf("the predecessor slot stayed after every local node accepted generation 8: %s", describe(s))
	}
	now = now.Add(time.Second)
	if s := pass(t, arbiter); s.Phase != api.ApprovalOverlapping || s.Pending != nil {
		t.Fatalf("overlapping: %s", describe(s))
	}

	// Retirement waits for the SPIRE CA bound (48h ca_ttl + 1h margin after the pass that read the successor). The
	// arbiter polls every 15 s, so after the jump one pass reads the nodes before their next heartbeat.
	now = switched.Add(48*time.Hour + time.Hour - 31*time.Second)
	pass(t, arbiter)
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	if s := pass(t, arbiter); s.Pending != nil || s.Phase != api.ApprovalOverlapping {
		t.Fatalf("retired before the bound: %s", describe(s))
	}
	// At the bound, a peer that is down holds the retirement: its nodes cannot report trusting the successor, its
	// evidence is unavailable, and nothing is written.
	now = now.Add(2 * time.Second)
	m.accept(now, p)
	arbiter.Peers["cmtc-b"] = failingReader{}
	s = pass(t, arbiter)
	if s.Pending != nil || m.slot("cmtc-issuer-approval-a") != nil || meta.IsStatusConditionTrue(s.Conditions, ConditionEvidenceReady) ||
		!strings.Contains(meta.FindStatusCondition(s.Conditions, ConditionBlocked).Message, trustprofile.HoldRetirementWaiting) {
		t.Fatalf("peer down: %s", describe(s))
	}
	for _, c := range s.Clusters {
		if c.Name == "cmtc-b" && c.Evidence != "Unavailable" {
			t.Fatalf("peer evidence: %+v", c)
		}
	}
	// A restarted arbiter resumes from the objects: it waits for one heartbeat, then retires the old key.
	arbiter.Peers["cmtc-b"] = m.peer
	restarted, producer := newArbiter(t, m, &now)
	if s := pass(t, restarted); s.Pending != nil || s.Current == nil || s.Current.Generation != 8 || m.slot("cmtc-issuer-approval-a") != nil || meta.IsStatusConditionTrue(s.Conditions, ConditionNodesConverged) {
		t.Fatalf("restart before a heartbeat: %s", describe(s))
	}
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	s = pass(t, restarted)
	if s.Pending == nil || s.Pending.Slot != "cmtc-issuer-approval-a" || s.Pending.Generation != 9 || s.Pending.Reason != trustprofile.ReasonIssuerRetired {
		t.Fatalf("retirement: %s", describe(s))
	}
	if keys := issuersOf(m.slot("cmtc-issuer-approval-a"), "cmtc-a"); strings.Join(keys, ",") != newKey.spki() {
		t.Fatalf("retired approval keys: %v", keys)
	}
	now = now.Add(time.Second)
	reconcileProfile(t, producer)
	m.mirrorPeerPublication()
	p = m.publication()
	if s := pass(t, restarted); s.Current == nil || s.Current.Generation != 9 || s.Pending != nil {
		t.Fatalf("after retirement publish: %s", describe(s))
	}

	// A slot written by the arbiter whose record update was lost is never published and is removed.
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	if s := pass(t, restarted); m.slot("cmtc-issuer-approval-b") != nil || s.Phase != api.ApprovalConverged {
		t.Fatalf("converged after retirement: %s", describe(s))
	}
	lost := *m.slot("cmtc-issuer-approval-a")
	lost.Generation = 10
	raw, err := json.Marshal(lost)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	if err := m.local.Create(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "cmtc-system", Name: "cmtc-issuer-approval-b", Labels: map[string]string{SlotLabel: "true"}},
		Immutable: &immutable, Data: map[string]string{trustprofile.ApprovalKey: string(raw)}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if s := pass(t, restarted); m.slot("cmtc-issuer-approval-b") != nil || s.Current.Generation != 9 {
		t.Fatalf("unrecorded slot kept: %s", describe(s))
	}
	// A ConfigMap with a slot name that the arbiter did not write is never deleted.
	if err := m.local.Create(context.Background(), &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "cmtc-system", Name: "cmtc-issuer-approval-b"}, Data: map[string]string{"x": "y"}}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	s = pass(t, restarted)
	var foreign corev1.ConfigMap
	if err := m.local.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-approval-b"}, &foreign); err != nil || blockedReason(s) != BlockForeignSlot {
		t.Fatalf("foreign slot: %v %s", err, describe(s))
	}
}

// The arbiter's configuration file is decoded strictly: every peer names its kubeconfig, the local cluster none.
func TestApprovalConfigIsStrict(t *testing.T) {
	good := `{"namespace":"cmtc-system","slots":["cmtc-issuer-approval-a","cmtc-issuer-approval-b"],"adoptSource":"cmtc-issuer-approval-g6","output":"cmtc-issuer-publication",
"rootConfigMap":"cmtc-mesh-root","certManagerNamespace":"cert-manager","rootIssuer":"cmtc-mesh-root","spireNamespace":"cilium-spire","spireConfigMap":"spire-server",
"rootSHA256":["` + strings.Repeat("a", 64) + `"],"minimumGeneration":6,"horizon":"696h","renewBefore":"168h","retirementMargin":"1h","reportMaxAge":"2m",
"clusters":[{"name":"cmtc-a","trustDomain":"cmtc-a.mesh.example","certificate":"cmtc-a-spire-intermediate","certificateUID":"u1"},
{"name":"cmtc-b","trustDomain":"cmtc-b.mesh.example","certificate":"cmtc-b-spire-intermediate","certificateUID":"u2","kubeconfig":"/etc/cmtc/peers/cmtc-b/kubeconfig"}]}`
	o, peers, err := DecodeApprovalConfig([]byte(good), "cmtc-a")
	if err != nil || o.Horizon != 696*time.Hour || o.MinimumGeneration != 6 || len(o.Clusters) != 2 || peers["cmtc-b"] != "/etc/cmtc/peers/cmtc-b/kubeconfig" || len(peers) != 1 {
		t.Fatalf("good config: %v %+v %v", err, o, peers)
	}
	for name, bad := range map[string]string{
		"unknown field":           strings.Replace(good, `"namespace"`, `"extra":1,"namespace"`, 1),
		"peer without kubeconfig": strings.Replace(good, `,"kubeconfig":"/etc/cmtc/peers/cmtc-b/kubeconfig"`, ``, 1),
		"relative kubeconfig":     strings.Replace(good, `/etc/cmtc/peers/cmtc-b/kubeconfig`, `peers/kubeconfig`, 1),
		"local with kubeconfig":   strings.Replace(good, `"certificateUID":"u1"}`, `"certificateUID":"u1","kubeconfig":"/x"}`, 1),
		"one slot":                strings.Replace(good, `,"cmtc-issuer-approval-b"`, ``, 1),
		"bad duration":            strings.Replace(good, `"horizon":"696h"`, `"horizon":"29 days"`, 1),
		"horizon over the limit":  strings.Replace(good, `"horizon":"696h"`, `"horizon":"720h"`, 1),
		"missing certificateUID":  strings.Replace(good, `"certificateUID":"u2",`, ``, 1),
		"two objects":             good + good,
	} {
		if _, _, err := DecodeApprovalConfig([]byte(bad), "cmtc-a"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, err := DecodeApprovalConfig([]byte(good), "cmtc-c"); err == nil {
		t.Error("a local cluster outside the configured clusters was accepted")
	}
	_ = fmt.Sprintf
}
