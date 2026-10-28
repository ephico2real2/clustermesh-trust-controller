package controller

import (
	"context"
	"testing"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// moveReports moves the ObservedAt of every report of one cluster, as its node agents' heartbeats would.
func moveReports(t *testing.T, m *passMesh, cluster string, at time.Time) {
	t.Helper()
	var list api.NodeTrustReportList
	if err := m.clientOf(cluster).List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	for i := range list.Items {
		list.Items[i].Status.ObservedAt = metav1.NewTime(at)
		if err := m.clientOf(cluster).Update(context.Background(), &list.Items[i]); err != nil {
			t.Fatal(err)
		}
	}
}

// converge runs the lifecycle test's bootstrap: every node reports, the arbiter writes generation 7, the producer
// publishes it and every node of both clusters accepts it.
func converge(t *testing.T, m *passMesh, arbiter *IssuerApprovalReconciler, producer *IssuerProfileReconciler, now *time.Time) *trustprofile.Publication {
	t.Helper()
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		for _, node := range []string{cluster + "-control-plane", cluster + "-worker"} {
			m.report(cluster, node, *now, api.PinsReport{State: api.PinsReadOnly, RootSHA256: arbiter.Options.RootPins}, api.ZtunnelReport{State: api.ZtunnelAbsent})
		}
	}
	pass(t, arbiter)
	*now = now.Add(30 * time.Second)
	m.heartbeat(*now)
	if s := pass(t, arbiter); s.Pending == nil || s.Pending.Generation != 7 {
		t.Fatalf("bootstrap: %s", describe(s))
	}
	*now = now.Add(time.Second)
	reconcileProfile(t, producer)
	m.mirrorPeerPublication()
	pass(t, arbiter)
	p := m.publication()
	*now = now.Add(30 * time.Second)
	m.accept(*now, p)
	if s := pass(t, arbiter); s.Phase != api.ApprovalConverged {
		t.Fatalf("converged: %s", describe(s))
	}
	return p
}

// renew makes one cluster's cert-manager objects show a new intermediate key at revision (rotationPolicy Always).
func renew(t *testing.T, m *passMesh, cluster string, revision int64, at time.Time) *passCA {
	t.Helper()
	ctx, c := context.Background(), m.clientOf(cluster)
	key := passCert(t, trustprofile.IntermediateCommonName(cluster), m.root, at.Truncate(time.Second), at.Truncate(time.Second).AddDate(1, 0, 0))
	for _, o := range certificateObjects(m, cluster, revision, key) {
		if o.GetObjectKind().GroupVersionKind().Kind != "Certificate" {
			if err := c.Create(ctx, o); err != nil {
				t.Fatal(err)
			}
			continue
		}
		current := object(certificateGVK)
		if err := c.Get(ctx, client.ObjectKeyFromObject(o), current); err != nil {
			t.Fatal(err)
		}
		current.Object["status"] = o.(*unstructured.Unstructured).Object["status"]
		if err := c.Update(ctx, current); err != nil {
			t.Fatal(err)
		}
	}
	return key
}

// A heartbeat that moved once after the last read of its cluster and then stopped is as old as that move, not as old
// as the read that noticed it: when no gate read the peer for two days, a report last written a day ago is stale.
func TestHeartbeatSeenAfterAnIdleReadIsNotFresh(t *testing.T) {
	m := newPassMesh(t)
	now := passNow
	arbiter, _ := newArbiter(t, m, &now)
	report := func(at time.Time) {
		for _, node := range []string{"cmtc-b-control-plane", "cmtc-b-worker"} {
			m.report("cmtc-b", node, at, api.PinsReport{State: api.PinsReadOnly, RootSHA256: arbiter.Options.RootPins}, api.ZtunnelReport{State: api.ZtunnelAbsent})
		}
	}
	fresh := func(at time.Time) int {
		views, err := arbiter.readNodes(context.Background(), "cmtc-b", m.peer, at)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, v := range views {
			if v.fresh {
				n++
			}
		}
		return n
	}
	report(passNow)
	if n := fresh(passNow); n != 0 {
		t.Fatalf("first sighting counted as fresh on %d nodes", n)
	}
	report(passNow.Add(30 * time.Second))
	if n := fresh(passNow.Add(45 * time.Second)); n != 2 {
		t.Fatalf("a live heartbeat is fresh on %d of 2 nodes", n)
	}
	report(passNow.Add(24 * time.Hour))
	if n := fresh(passNow.Add(48 * time.Hour)); n != 0 {
		t.Fatalf("a heartbeat written a day ago, then frozen, counts as fresh on %d nodes", n)
	}
	report(passNow.Add(48*time.Hour + 30*time.Second))
	if n := fresh(passNow.Add(48*time.Hour + 45*time.Second)); n != 2 {
		t.Fatalf("a live heartbeat after the idle read is fresh on %d of 2 nodes", n)
	}
}

// The write gate reads the peer only when a generation is due. A peer whose node agents stopped a day after the last
// such read must block the next generation, not pass the gate because its heartbeat differs from that old read.
func TestFrozenPeerReportBlocksTheNextGeneration(t *testing.T) {
	m := newPassMesh(t)
	now := passNow
	arbiter, producer := newArbiter(t, m, &now)
	converge(t, m, arbiter, producer, &now)
	moveReports(t, m, "cmtc-b", now.Add(24*time.Hour))
	now = now.Add(48 * time.Hour)
	reconcileProfile(t, producer)
	m.mirrorPeerPublication()
	moveReports(t, m, "cmtc-a", now)
	pass(t, arbiter)
	now = now.Add(30 * time.Second)
	moveReports(t, m, "cmtc-a", now)
	renew(t, m, "cmtc-a", 2, now)
	if s := pass(t, arbiter); s.Pending != nil || blockedReason(s) != BlockMeshNotConverged {
		t.Fatalf("a generation was written while the peer's newest reports are a day old: %s", describe(s))
	}
	now = now.Add(30 * time.Second)
	moveReports(t, m, "cmtc-a", now)
	moveReports(t, m, "cmtc-b", now)
	if s := pass(t, arbiter); s.Pending == nil || s.Pending.Reason != trustprofile.ReasonIssuerAdded {
		t.Fatalf("the renewal did not go ahead once the peer beat again: %s", describe(s))
	}
}

// Operator decision 2026-10-27T16:28Z: cert-manager's own approver approves the CertificateRequests and no
// CertificateRequestPolicy exists. The SPIRE CA bound then comes from SPIRE's server.conf ca_ttl, and the old key of a
// renewed intermediate retires after it.
func TestRenewedKeyRetiresWithoutCertificateRequestPolicies(t *testing.T) {
	m := newPassMesh(t)
	ctx := context.Background()
	policyKind := schema.GroupVersionKind{Group: "policy.cert-manager.io", Version: "v1alpha1", Kind: "CertificateRequestPolicy"}
	for _, cluster := range []string{"cmtc-a", "cmtc-b"} {
		c := m.clientOf(cluster)
		policy := object(policyKind)
		policy.SetName(cluster + "-spire-ca")
		if err := client.IgnoreNotFound(c.Delete(ctx, policy)); err != nil {
			t.Fatal(err)
		}
		var conf corev1.ConfigMap
		if err := c.Get(ctx, client.ObjectKey{Namespace: "cilium-spire", Name: "spire-server"}, &conf); err != nil {
			t.Fatal(err)
		}
		conf.Data["server.conf"] = "server {\n  ca_ttl = \"48h\"\n}\nUpstreamAuthority \"cert-manager\" {\n  plugin_data {\n    namespace = \"cilium-spire\"\n    issuer_name = \"" + cluster + "-spire-intermediate\"\n  }\n}\n"
		if err := c.Update(ctx, &conf); err != nil {
			t.Fatal(err)
		}
	}
	now := passNow
	arbiter, producer := newArbiter(t, m, &now)
	converge(t, m, arbiter, producer, &now)
	switched := now.Add(time.Minute)
	now = switched
	newKey := renew(t, m, "cmtc-a", 2, now)
	m.heartbeat(now)
	if s := pass(t, arbiter); s.Pending == nil || s.Pending.Reason != trustprofile.ReasonIssuerAdded {
		t.Fatalf("renewal: %s", describe(s))
	}
	now = now.Add(time.Second)
	reconcileProfile(t, producer)
	m.mirrorPeerPublication()
	p := m.publication()
	pass(t, arbiter)
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	pass(t, arbiter)
	// Past ca_ttl (48h) and the 1h margin after the pass that read the successor; every node trusts it. Two passes
	// with a heartbeat between them, as the 15 s poll gives.
	now = switched.Add(49*time.Hour + time.Minute)
	reconcileProfile(t, producer)
	m.mirrorPeerPublication()
	p = m.publication()
	m.accept(now, p)
	pass(t, arbiter)
	now = now.Add(30 * time.Second)
	m.accept(now, p)
	s := pass(t, arbiter)
	if s.Pending == nil || s.Pending.Reason != trustprofile.ReasonIssuerRetired {
		t.Fatalf("the old key did not retire without a CertificateRequestPolicy: %s", describe(s))
	}
	if keys := issuersOf(m.slot(s.Pending.Slot), "cmtc-a"); len(keys) != 1 || keys[0] != newKey.spki() {
		t.Fatalf("retired approval keys: %v", keys)
	}
}
