package spireregistrar

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	stypes "github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func testUID(name string) ktypes.UID {
	return ktypes.UID(uuid.NewSHA1(uuid.NameSpaceURL, []byte(name)).String())
}
func fixture(t *testing.T) (Options, client.Client, *corev1.Pod) {
	t.Helper()
	image := "example.test/component@sha256:" + strings.Repeat("a", 64)
	o := Options{ClusterName: "cmtc-a", ClusterUID: testUID("cluster"), TrustDomain: "cmtc-a.mesh.example", InstallationID: string(testUID("installation")), Namespaces: []NamespaceApproval{{Name: "orders", UID: testUID("orders"), ServiceAccounts: map[string]ktypes.UID{"api": testUID("api")}}}, Agent: DaemonApproval{Namespace: "cilium-spire", NamespaceUID: testUID("spire-ns"), Name: "spire-agent", UID: testUID("agent-ds"), ServiceAccount: "spire-agent", ServiceAccountUID: testUID("agent-sa"), Container: "spire-agent", Image: image}, Delegate: DaemonApproval{Namespace: "kube-system", NamespaceUID: testUID("cluster"), Name: "ztunnel-cilium", UID: testUID("delegate-ds"), ServiceAccount: "ztunnel-cilium", ServiceAccountUID: testUID("delegate-sa"), Container: "ztunnel", Image: image}}
	meta := func(name, ns string, id ktypes.UID) metav1.ObjectMeta {
		return metav1.ObjectMeta{Name: name, Namespace: ns, UID: id, ResourceVersion: "1"}
	}
	ns := &corev1.Namespace{ObjectMeta: meta("orders", "", testUID("orders"))}
	ns.Labels = map[string]string{"io.cilium/mtls-enabled": "true"}
	pod := &corev1.Pod{ObjectMeta: meta("api-0", "orders", testUID("pod")), Spec: corev1.PodSpec{NodeName: "worker", ServiceAccountName: "api"}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	makeDS := func(a DaemonApproval) *appsv1.DaemonSet {
		return &appsv1.DaemonSet{ObjectMeta: meta(a.Name, a.Namespace, a.UID)}
	}
	makePod := func(a DaemonApproval, name string) *corev1.Pod {
		p := &corev1.Pod{ObjectMeta: meta(name, a.Namespace, testUID(name)), Spec: corev1.PodSpec{NodeName: "worker", ServiceAccountName: a.ServiceAccount, Containers: []corev1.Container{{Name: a.Container, Image: a.Image}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
		yes := true
		p.OwnerReferences = []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: a.Name, UID: a.UID, Controller: &yes}}
		return p
	}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = appsv1.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.Namespace{ObjectMeta: meta("kube-system", "", o.ClusterUID)}, &corev1.Namespace{ObjectMeta: meta("cilium-spire", "", o.Agent.NamespaceUID)}, ns,
		&corev1.ServiceAccount{ObjectMeta: meta("api", "orders", testUID("api"))}, &corev1.ServiceAccount{ObjectMeta: meta(o.Agent.ServiceAccount, o.Agent.Namespace, o.Agent.ServiceAccountUID)}, &corev1.ServiceAccount{ObjectMeta: meta(o.Delegate.ServiceAccount, o.Delegate.Namespace, o.Delegate.ServiceAccountUID)},
		makeDS(o.Agent), makeDS(o.Delegate), makePod(o.Agent, "spire-agent-1"), makePod(o.Delegate, "ztunnel-1"), pod,
		&corev1.Node{ObjectMeta: meta("worker", "", testUID("node"))},
	).Build()
	return o, c, pod
}

type memoryEntries struct {
	entryv1.EntryClient
	rows            map[string]*stypes.Entry
	createErr       bool
	malformedCreate bool
	denyUpdate      bool
	lostDeleteACK   bool
	operations      []string
}

func newEntries() *memoryEntries { return &memoryEntries{rows: map[string]*stypes.Entry{}} }
func entrySelected(e *stypes.Entry, f *entryv1.ListEntriesRequest_Filter) bool {
	if e == nil || f == nil {
		return false
	}
	if f.ByHint != nil && e.Hint != f.ByHint.Value {
		return false
	}
	if id := f.BySpiffeId; id != nil && (e.SpiffeId == nil || e.SpiffeId.TrustDomain != id.TrustDomain || e.SpiffeId.Path != id.Path) {
		return false
	}
	if id := f.ByParentId; id != nil && (e.ParentId == nil || e.ParentId.TrustDomain != id.TrustDomain || e.ParentId.Path != id.Path) {
		return false
	}
	return true
}
func (m *memoryEntries) ListEntries(_ context.Context, in *entryv1.ListEntriesRequest, _ ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	out := &entryv1.ListEntriesResponse{}
	for _, e := range m.rows {
		if entrySelected(e, in.Filter) {
			out.Entries = append(out.Entries, proto.Clone(e).(*stypes.Entry))
		}
	}
	return out, nil
}
func (m *memoryEntries) GetEntry(_ context.Context, in *entryv1.GetEntryRequest, _ ...grpc.CallOption) (*stypes.Entry, error) {
	if e := m.rows[in.Id]; e != nil {
		return proto.Clone(e).(*stypes.Entry), nil
	}
	return nil, status.Error(codes.NotFound, "absent")
}
func (m *memoryEntries) BatchCreateEntry(_ context.Context, in *entryv1.BatchCreateEntryRequest, _ ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
	e := proto.Clone(in.Entries[0]).(*stypes.Entry)
	m.rows[e.Id] = e
	m.operations = append(m.operations, "create:"+e.Id)
	if m.createErr {
		return nil, status.Error(codes.Unavailable, "response lost after server commit")
	}
	if m.malformedCreate {
		return &entryv1.BatchCreateEntryResponse{}, nil
	}
	return &entryv1.BatchCreateEntryResponse{Results: []*entryv1.BatchCreateEntryResponse_Result{{Status: &stypes.Status{Code: int32(codes.OK)}, Entry: proto.Clone(e).(*stypes.Entry)}}}, nil
}
func (m *memoryEntries) BatchUpdateEntry(_ context.Context, in *entryv1.BatchUpdateEntryRequest, _ ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
	e := in.Entries[0]
	if !in.InputMask.ExpiresAt {
		panic("unmasked authority update")
	}
	if m.denyUpdate {
		return &entryv1.BatchUpdateEntryResponse{Results: []*entryv1.BatchUpdateEntryResponse_Result{{Status: &stypes.Status{Code: int32(codes.PermissionDenied)}}}}, nil
	}
	m.rows[e.Id].ExpiresAt = e.ExpiresAt
	return &entryv1.BatchUpdateEntryResponse{Results: []*entryv1.BatchUpdateEntryResponse_Result{{Status: &stypes.Status{Code: int32(codes.OK)}, Entry: proto.Clone(m.rows[e.Id]).(*stypes.Entry)}}}, nil
}
func (m *memoryEntries) BatchDeleteEntry(_ context.Context, in *entryv1.BatchDeleteEntryRequest, _ ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	id := in.Ids[0]
	delete(m.rows, id)
	m.operations = append(m.operations, "delete:"+id)
	if m.lostDeleteACK {
		return nil, status.Error(codes.Unavailable, "delete ACK lost")
	}
	return &entryv1.BatchDeleteEntryResponse{Results: []*entryv1.BatchDeleteEntryResponse_Result{{Status: &stypes.Status{Code: int32(codes.OK)}, Id: id}}}, nil
}

func TestExactEntriesBindAgentNodeAndWorkloadIncarnations(t *testing.T) {
	o, c, _ := fixture(t)
	now := time.Now()
	snapshot, err := (Source{Reader: c, Options: o}).Collect(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 3 {
		t.Fatalf("want one agent alias plus exact workload and delegate, got %d", len(snapshot.Entries))
	}
	for _, e := range snapshot.Entries {
		if e.Admin || e.Downstream || e.StoreSvid || len(e.FederatesWith) > 0 || e.X509SvidTtl != 120 || e.ExpiresAt != now.Add(90*time.Second).Unix() {
			t.Fatalf("entry broadens authority or expiry: %v", e)
		}
		selectors := map[string]bool{}
		for _, s := range e.Selectors {
			selectors[s.Type+":"+s.Value] = true
		}
		if e.ParentId.Path == "/spire/server" {
			if !selectors["k8s_psat:agent_node_uid:"+string(testUID("node"))] || !selectors["k8s_psat:agent_pod_uid:"+string(testUID("spire-agent-1"))] {
				t.Fatal("alias lacks exact node and attested agent UID")
			}
		} else if !strings.HasPrefix(e.ParentId.Path, "/cmtc/agents/"+string(testUID("node"))+"/") {
			t.Fatal("workload is not parented to exact PSAT alias")
		}
	}
}
func TestNamespaceExclusionAndUnenrollmentDeleteOnlyOwnedWorkload(t *testing.T) {
	for _, mode := range []string{"unenroll", "exclude", "namespace-replacement", "sa-replacement"} {
		t.Run(mode, func(t *testing.T) {
			o, c, _ := fixture(t)
			entries := newEntries()
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
			now := time.Now()
			if _, err := r.Reconcile(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			foreign := &stypes.Entry{Id: "foreign", Hint: "some-other-controller"}
			entries.rows[foreign.Id] = foreign
			var ns corev1.Namespace
			_ = c.Get(context.Background(), client.ObjectKey{Name: "orders"}, &ns)
			switch mode {
			case "unenroll":
				delete(ns.Labels, "io.cilium/mtls-enabled")
				_ = c.Update(context.Background(), &ns)
			case "exclude":
				r.Source.Options.ExcludedNamespaces = []string{"orders"}
			case "namespace-replacement":
				ns.UID = testUID("replacement")
				_ = c.Update(context.Background(), &ns)
			case "sa-replacement":
				var sa corev1.ServiceAccount
				_ = c.Get(context.Background(), client.ObjectKey{Namespace: "orders", Name: "api"}, &sa)
				sa.UID = testUID("replacement-sa")
				_ = c.Update(context.Background(), &sa)
			}
			_, err := r.Reconcile(context.Background(), now.Add(time.Second))
			if mode == "namespace-replacement" || mode == "sa-replacement" {
				if err == nil {
					t.Fatal("changed UID was accepted")
				}
				if err := r.Withdraw(context.Background()); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries.rows {
				if e.SpiffeId != nil && e.SpiffeId.Path == "/ns/orders/sa/api" {
					t.Fatal("unenrolled workload row survived")
				}
			}
			if entries.rows[foreign.Id] != foreign {
				t.Fatal("foreign registration changed")
			}
		})
	}
}
func TestPodReplacementRetiresOldUIDBeforePublishingNew(t *testing.T) {
	o, c, pod := fixture(t)
	entries := newEntries()
	r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
	now := time.Now()
	if _, err := r.Reconcile(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	old := ""
	for id, e := range entries.rows {
		if e.SpiffeId.Path == "/ns/orders/sa/api" {
			old = id
		}
	}
	if err := c.Delete(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	pod.UID = testUID("new-pod")
	pod.ResourceVersion = ""
	if err := c.Create(context.Background(), pod); err != nil {
		t.Fatal(err)
	}
	entries.operations = nil
	if _, err := r.Reconcile(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if entries.rows[old] != nil || len(entries.operations) < 2 || entries.operations[0] != "delete:"+old {
		t.Fatalf("old exact UID was not retired first: %v", entries.operations)
	}
}
func TestSPIREACKFailuresRestartAndRetainedRows(t *testing.T) {
	for _, mode := range []string{"create-ack-lost", "missing-result", "update-denied", "delete-ack-lost"} {
		t.Run(mode, func(t *testing.T) {
			o, c, _ := fixture(t)
			entries := newEntries()
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
			now := time.Now()
			if mode == "create-ack-lost" {
				entries.createErr = true
			}
			if mode == "missing-result" {
				entries.malformedCreate = true
			}
			_, err := r.Reconcile(context.Background(), now)
			if mode == "create-ack-lost" || mode == "missing-result" {
				if err == nil {
					t.Fatal("unacknowledged create accepted")
				}
				entries.createErr = false
				entries.malformedCreate = false
			} else if err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(context.Background(), now.Add(time.Second)); err != nil {
				t.Fatal("restart failed to read back retained rows:", err)
			}
			if mode == "update-denied" {
				entries.denyUpdate = true
				if _, err := r.Reconcile(context.Background(), now.Add(2*time.Second)); err == nil {
					t.Fatal("per-entry renewal denial accepted")
				}
				entries.denyUpdate = false
				recovered := now.Add(3 * time.Second)
				if _, err := r.Reconcile(context.Background(), recovered); err != nil {
					t.Fatal("expiry renewal did not recover:", err)
				}
				for _, row := range entries.rows {
					if row.ExpiresAt != recovered.Add(90*time.Second).Unix() {
						t.Fatalf("recovered expiry = %d, want %d", row.ExpiresAt, recovered.Add(90*time.Second).Unix())
					}
				}
			}
			if mode == "delete-ack-lost" {
				entries.lostDeleteACK = true
				if err := r.Withdraw(context.Background()); err == nil {
					t.Fatal("lost deletion ACK accepted")
				}
				entries.lostDeleteACK = false
			}
			if err := r.Withdraw(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(entries.rows) != 0 {
				t.Fatal("owned rows remain after verified retry")
			}
		})
	}
}
func TestExactRowCollisionNeverAdopted(t *testing.T) {
	o, c, _ := fixture(t)
	now := time.Now()
	s, err := (Source{Reader: c, Options: o}).Collect(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"foreign-owner", "wrong-selector", "admin", "duplicate-selector"} {
		t.Run(mode, func(t *testing.T) {
			want := s.Entries[0]
			bad := proto.Clone(want).(*stypes.Entry)
			switch mode {
			case "foreign-owner":
				bad.Hint = "foreign"
			case "wrong-selector":
				bad.Selectors[0].Value = "wrong"
			case "admin":
				bad.Admin = true
			case "duplicate-selector":
				bad.Selectors = append(bad.Selectors, proto.Clone(bad.Selectors[0]).(*stypes.Selector))
			}
			entries := newEntries()
			entries.rows[bad.Id] = bad
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
			if err := r.upsert(context.Background(), want); err == nil {
				t.Fatal("conflicting row was adopted")
			}
			if !proto.Equal(entries.rows[bad.Id], bad) {
				t.Fatal("conflicting row changed")
			}
		})
	}
}

type failReader struct{ client.Reader }

func (r failReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("API unavailable")
}
func TestSourceAPIFailureAndRecheckCloseReadiness(t *testing.T) {
	o, c, p := fixture(t)
	s, err := (Source{Reader: c, Options: o}).Collect(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p.Spec.ServiceAccountName = "different"
	if err := c.Update(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := s.Recheck(context.Background(), c); err == nil {
		t.Fatal("live Pod change did not invalidate collected snapshot")
	}
	entries := newEntries()
	r := Registrar{Source: Source{Reader: failReader{c}, Options: o}, Entries: entries}
	if _, err := r.Reconcile(context.Background(), time.Now()); err == nil {
		t.Fatal("API failure accepted")
	}
	if len(entries.rows) != 0 {
		t.Fatal("API failure published registrations")
	}
}

func TestAgentAndNodeReplacementReparentEveryOwnedWorkload(t *testing.T) {
	for _, mode := range []string{"agent", "node"} {
		t.Run(mode, func(t *testing.T) {
			o, c, _ := fixture(t)
			entries := newEntries()
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
			now := time.Now()
			if _, err := r.Reconcile(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			previous := map[string]bool{}
			for id := range entries.rows {
				previous[id] = true
			}
			if mode == "agent" {
				var agent corev1.Pod
				if err := c.Get(context.Background(), client.ObjectKey{Namespace: o.Agent.Namespace, Name: "spire-agent-1"}, &agent); err != nil {
					t.Fatal(err)
				}
				if err := c.Delete(context.Background(), &agent); err != nil {
					t.Fatal(err)
				}
				agent.UID = testUID("replacement-agent")
				agent.ResourceVersion = ""
				if err := c.Create(context.Background(), &agent); err != nil {
					t.Fatal(err)
				}
			} else {
				var node corev1.Node
				_ = c.Get(context.Background(), client.ObjectKey{Name: "worker"}, &node)
				node.UID = testUID("replacement-node")
				if err := c.Update(context.Background(), &node); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := r.Reconcile(context.Background(), now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if len(entries.rows) != 3 {
				t.Fatalf("unexpected replacement rows: %d", len(entries.rows))
			}
			for id := range entries.rows {
				if previous[id] {
					t.Fatal("old source incarnation row survived")
				}
			}
		})
	}
}
func TestDelegateControllerImageAndServiceAccountBinding(t *testing.T) {
	for _, mode := range []string{"owner", "image", "service-account"} {
		t.Run(mode, func(t *testing.T) {
			o, c, _ := fixture(t)
			var pod corev1.Pod
			_ = c.Get(context.Background(), client.ObjectKey{Namespace: o.Delegate.Namespace, Name: "ztunnel-1"}, &pod)
			switch mode {
			case "owner":
				pod.OwnerReferences[0].UID = testUID("foreign-daemon")
			case "image":
				pod.Spec.Containers[0].Image = "unapproved-image"
			case "service-account":
				pod.Spec.ServiceAccountName = "default"
			}
			if err := c.Update(context.Background(), &pod); err != nil {
				t.Fatal(err)
			}
			snapshot, err := (Source{Reader: c, Options: o}).Collect(context.Background(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range snapshot.Entries {
				if entry.SpiffeId.Path == "/ztunnel-proxy" {
					t.Fatal("unapproved delegate received a registration")
				}
			}
		})
	}
}

func TestSourceOutagePreservesExpiryAndRecoveryRenewsIt(t *testing.T) {
	o, c, _ := fixture(t)
	entries := newEntries()
	r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := r.Reconcile(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	if len(entries.rows) != 3 {
		t.Fatalf("rows = %d", len(entries.rows))
	}
	for _, row := range entries.rows {
		if row.ExpiresAt != now.Add(90*time.Second).Unix() {
			t.Fatalf("initial expiry = %d", row.ExpiresAt)
		}
	}
	r.Source.Reader = failReader{c}
	if _, err := r.Reconcile(context.Background(), now.Add(time.Minute)); err == nil {
		t.Fatal("source outage accepted")
	}
	for _, row := range entries.rows {
		if row.ExpiresAt != now.Add(90*time.Second).Unix() {
			t.Fatal("source outage changed an entry expiry")
		}
	}
	r.Source.Reader = c
	later := now.Add(2 * time.Minute)
	if _, err := r.Reconcile(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	if len(entries.rows) != 3 {
		t.Fatalf("recovery rows = %d", len(entries.rows))
	}
	for _, row := range entries.rows {
		if row.ExpiresAt != later.Add(90*time.Second).Unix() {
			t.Fatalf("recovered expiry = %d", row.ExpiresAt)
		}
	}
}

func legacyBroad(o Options, path, ns, sa string) *stypes.Entry {
	return &stypes.Entry{
		Id:        uuid.NewSHA1(uuid.NameSpaceURL, []byte("legacy:"+path)).String(),
		SpiffeId:  &stypes.SPIFFEID{TrustDomain: o.TrustDomain, Path: path},
		ParentId:  &stypes.SPIFFEID{TrustDomain: o.TrustDomain, Path: "/ztunnel"},
		Selectors: []*stypes.Selector{{Type: "k8s", Value: "sa:" + sa}, {Type: "k8s", Value: "ns:" + ns}},
	}
}

type wrongIdentityList struct {
	*memoryEntries
	wrong *stypes.Entry
}

func (m wrongIdentityList) ListEntries(_ context.Context, in *entryv1.ListEntriesRequest, _ ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	if in.Filter.BySpiffeId != nil {
		return &entryv1.ListEntriesResponse{Entries: []*stypes.Entry{proto.Clone(m.wrong).(*stypes.Entry)}}, nil
	}
	return &entryv1.ListEntriesResponse{}, nil
}

func TestSingleWriterRejectsMismatchedIdentityFilterBeforeCleanup(t *testing.T) {
	o, _, _ := fixture(t)
	o.Namespaces[0].ServiceAccounts["other"] = testUID("other")
	entries := newEntries()
	wrong := legacyBroad(o, "/ns/orders/sa/other", "orders", "other")
	entries.rows[wrong.Id] = proto.Clone(wrong).(*stypes.Entry)
	r := Registrar{Source: Source{Options: o}, Entries: wrongIdentityList{memoryEntries: entries, wrong: wrong}}
	if err := r.enforceSingleWriter(context.Background(), nil); err == nil {
		t.Fatal("SPIRE ignored the identity filter but cleanup continued")
	}
	if len(entries.operations) != 0 || !proto.Equal(entries.rows[wrong.Id], wrong) {
		t.Fatal("mismatched filter response caused registration deletion")
	}
}

func TestLegacyBroadEntryRetiredAndForeignWriterKept(t *testing.T) {
	for _, mode := range []string{"enrolled", "unenrolled", "outside-approval", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			o, c, _ := fixture(t)
			if mode == "unenrolled" {
				var ns corev1.Namespace
				if err := c.Get(context.Background(), client.ObjectKey{Name: "orders"}, &ns); err != nil {
					t.Fatal(err)
				}
				ns.Labels = nil
				if err := c.Update(context.Background(), &ns); err != nil {
					t.Fatal(err)
				}
			}
			entries := newEntries()
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
			now := time.Now().UTC().Truncate(time.Second)
			if mode == "foreign" {
				if _, err := r.Reconcile(context.Background(), now); err != nil {
					t.Fatal(err)
				}
			}
			legacy := legacyBroad(o, "/ns/orders/sa/api", "orders", "api")
			if mode == "outside-approval" {
				legacy = legacyBroad(o, "/ns/other/sa/api", "other", "api")
			}
			if mode == "foreign" {
				var workload *stypes.Entry
				for _, row := range entries.rows {
					if row.SpiffeId.Path == "/ns/orders/sa/api" {
						workload = proto.Clone(row).(*stypes.Entry)
					}
				}
				if workload == nil {
					t.Fatal("exact workload missing before foreign collision")
				}
				foreign := proto.Clone(workload).(*stypes.Entry)
				foreign.Id = uuid.NewSHA1(uuid.NameSpaceURL, []byte("foreign-writer")).String()
				foreign.Hint = "other-writer"
				foreign.Admin = true
				entries.rows[foreign.Id] = foreign
				_, err := r.Reconcile(context.Background(), now)
				var duplicate *DuplicateWriterError
				if !errors.As(err, &duplicate) || duplicate.Path != "/ns/orders/sa/api" {
					t.Fatal(err)
				}
				if !proto.Equal(entries.rows[workload.Id], workload) || !proto.Equal(entries.rows[foreign.Id], foreign) {
					t.Fatal("foreign collision changed an exact row or the foreign row")
				}
				return
			}
			entries.rows[legacy.Id] = proto.Clone(legacy).(*stypes.Entry)
			if _, err := r.Reconcile(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			_, legacyRemains := entries.rows[legacy.Id]
			if mode == "outside-approval" && !legacyRemains {
				t.Fatal("legacy row outside the approved set was deleted")
			}
			if mode != "outside-approval" && legacyRemains {
				t.Fatal("approved legacy broad row survived")
			}
			for _, row := range entries.rows {
				if row.ParentId.Path == "/ztunnel" && mode != "outside-approval" {
					t.Fatal("broad parent remains for an approved identity")
				}
				if mode == "unenrolled" && row.SpiffeId.Path == "/ns/orders/sa/api" {
					t.Fatal("unenrolled namespace received a workload registration")
				}
			}
			if mode == "enrolled" {
				found := false
				for _, row := range entries.rows {
					if row.Hint != o.Hint() || row.SpiffeId.Path != "/ns/orders/sa/api" {
						continue
					}
					for _, sel := range row.Selectors {
						if sel.Value == "pod-uid:"+string(testUID("pod")) {
							found = true
						}
					}
				}
				if !found {
					t.Fatal("exact pod-bound workload row missing after legacy retirement")
				}
			}
		})
	}
}
