package controller

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func slotObject(t *testing.T, name string, uid types.UID, a trustprofile.Approval) *corev1.ConfigMap {
	t.Helper()
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "cmtc-system", UID: uid, Labels: map[string]string{SlotLabel: "true"}},
		Immutable: &immutable, Data: map[string]string{trustprofile.ApprovalKey: string(raw)}}
}

func setRecord(t *testing.T, c client.Client, current, pending *api.ApprovalRef) {
	t.Helper()
	var record api.IssuerApproval
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: api.IssuerApprovalName}, &record); err != nil {
		t.Fatal(err)
	}
	record.Status.Current, record.Status.Pending = current, pending
	if err := c.Update(context.Background(), &record); err != nil {
		t.Fatal(err)
	}
}

// The producer publishes the slot the arbiter names: the pending one once it validates, then the current one. Its
// own floors still refuse an older generation, so an arbiter that names an old slot gets a withdrawal, never a
// rollback. Without a source to follow the producer writes nothing.
func TestProducerFollowsTheArbitersSlots(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	g1 := producerApproval(t, now)
	g2 := g1
	g2.Generation = 2
	a, b := slotObject(t, "cmtc-issuer-approval-a", "slot-a-1", g1), slotObject(t, "cmtc-issuer-approval-b", "slot-b-1", g2)
	output := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "cmtc-issuer-publication", Namespace: "cmtc-system", UID: "output-v1", Labels: map[string]string{trustprofile.OutputLabel: "true"}}}
	record := &api.IssuerApproval{ObjectMeta: metav1.ObjectMeta{Namespace: "cmtc-system", Name: api.IssuerApprovalName},
		Status: api.IssuerApprovalStatus{Pending: &api.ApprovalRef{Slot: a.Name, UID: string(a.UID), Generation: 1}}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := &profileFaultClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(a, b, output, record).Build()}
	roots := []string{g1.Roots[0].SHA256}
	arbiter := &IssuerApprovalReconciler{Reader: c, Now: func() time.Time { return now },
		Options: IssuerApprovalOptions{Namespace: "cmtc-system", Slots: [2]string{a.Name, b.Name}, Output: output.Name, LocalCluster: "cmtc-a", RootPins: roots}}
	metrics, err := trustprofile.NewMetrics(prometheus.NewRegistry(), "cmtc-a")
	if err != nil {
		t.Fatal(err)
	}
	producer := &IssuerProfileReconciler{Client: c, Reader: c, Follow: arbiter.FollowedSource, Metrics: metrics, Now: func() time.Time { return now },
		Options: IssuerProfileOptions{Output: client.ObjectKeyFromObject(output), OutputUID: output.UID, MinimumGeneration: 1, RootPins: roots, LocalCluster: "cmtc-a"}}
	if err := producer.Options.ValidateFollowed(); err != nil {
		t.Fatal(err)
	}
	fixed := producer.Options
	fixed.Source, fixed.SourceUID = client.ObjectKeyFromObject(a), a.UID
	if err := fixed.ValidateFollowed(); err == nil {
		t.Fatal("a followed producer accepted a fixed source")
	}
	key := client.ObjectKeyFromObject(output)

	reconcileProfile(t, producer)
	if _, p := readProfile(t, c, key); p.State != "published" || p.Source.Name != a.Name || p.ExpectedSourceUID != "slot-a-1" || p.AcceptedGeneration != 1 {
		t.Fatalf("pending slot a: %+v", p)
	}
	setRecord(t, c, &api.ApprovalRef{Slot: a.Name, UID: string(a.UID), Generation: 1}, &api.ApprovalRef{Slot: b.Name, UID: string(b.UID), Generation: 2})
	reconcileProfile(t, producer)
	if _, p := readProfile(t, c, key); p.State != "published" || p.Source.Name != b.Name || p.AcceptedSourceUID != "slot-b-1" || p.AcceptedGeneration != 2 {
		t.Fatalf("pending slot b: %+v", p)
	}
	setRecord(t, c, &api.ApprovalRef{Slot: a.Name, UID: string(a.UID), Generation: 1}, nil)
	reconcileProfile(t, producer)
	if _, p := readProfile(t, c, key); p.State != "withdrawn" || p.Reason != "GenerationRollback" || p.AcceptedGeneration != 2 {
		t.Fatalf("an older slot named as current: %+v", p)
	}

	// The record is gone and the publication names a slot: the producer keeps following that slot.
	if err := c.Delete(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if got, uid, err := arbiter.FollowedSource(context.Background(), &trustprofile.Publication{Source: trustprofile.Source{Namespace: "cmtc-system", Name: b.Name, UID: "slot-b-1"}, AcceptedSourceUID: "slot-b-1"}); err != nil || got.Name != b.Name || uid != "slot-b-1" {
		t.Fatalf("follow the publication's slot: %v %v %v", got, uid, err)
	}
	// A source the arbiter does not own is never followed, and the producer then writes nothing.
	if _, _, err := arbiter.FollowedSource(context.Background(), &trustprofile.Publication{Source: trustprofile.Source{Namespace: "cmtc-system", Name: "cmtc-issuer-approval-g6", UID: "g6"}, AcceptedSourceUID: "g6"}); err == nil {
		t.Fatal("followed a source that is neither a slot nor the adopted source")
	}
	arbiter.Options.AdoptSource = "cmtc-issuer-approval-g6"
	if got, _, err := arbiter.FollowedSource(context.Background(), &trustprofile.Publication{Source: trustprofile.Source{Namespace: "cmtc-system", Name: "cmtc-issuer-approval-g6", UID: "g6"}, AcceptedSourceUID: "g6"}); err != nil || got.Name != "cmtc-issuer-approval-g6" {
		t.Fatalf("adopted source: %v %v", got, err)
	}
	empty := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "fresh-output", Namespace: "cmtc-system", UID: "output-v2", Labels: map[string]string{trustprofile.OutputLabel: "true"}}}
	if err := c.Create(context.Background(), empty); err != nil {
		t.Fatal(err)
	}
	updates := c.updates
	fresh := &IssuerProfileReconciler{Client: c, Reader: c, Follow: arbiter.FollowedSource, Metrics: metrics, Now: producer.Now, Options: producer.Options}
	fresh.Options.Output, fresh.Options.OutputUID = client.ObjectKeyFromObject(empty), empty.UID
	if _, err := fresh.Reconcile(context.Background(), ctrl.Request{}); err == nil || !strings.Contains(err.Error(), "no followed approval source") {
		t.Fatalf("no source to follow: %v", err)
	}
	if c.updates != updates {
		t.Fatal("the producer wrote without a source to follow")
	}
}
