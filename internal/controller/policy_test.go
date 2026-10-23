package controller

import (
	"context"
	"testing"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/policy"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestObserveCannotEnrollOrAssertProtection(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = api.AddToScheme(scheme)
	p := &api.NamespaceMTLSPolicy{ObjectMeta: metav1.ObjectMeta{Name: "test", Generation: 3}, Spec: api.NamespaceMTLSPolicySpec{Enrollment: api.Enrollment{SelectionMode: "AllEligible"}, Enforcement: api.Enforcement{Mode: "Observe"}}}
	app := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "a"}}
	existing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "existing", Labels: map[string]string{policy.EnrollmentLabel: "true"}}}
	c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(p).WithObjects(p, app, existing).Build()
	r := &PolicyReconciler{Client: c, Metrics: telemetry.New(prometheus.NewRegistry(), "test", "")}
	request := ctrl.Request{NamespacedName: client.ObjectKey{Name: p.Name}}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	var got api.NamespaceMTLSPolicy
	_ = c.Get(context.Background(), request.NamespacedName, &got)
	if got.Status.Selected != 2 || got.Status.ObservedGeneration != 3 || got.Status.Labeled != 1 {
		t.Fatalf("unexpected status: %+v", got.Status)
	}
	condition := meta.FindStatusCondition(got.Status.Conditions, "EnforcementVerified")
	if condition == nil || condition.Status != metav1.ConditionUnknown {
		t.Fatal("observation asserted enforcement")
	}
	var actual corev1.Namespace
	_ = c.Get(context.Background(), client.ObjectKey{Name: app.Name}, &actual)
	if actual.Labels[policy.EnrollmentLabel] != "" {
		t.Fatal("Observe mutated namespace")
	}
	_ = c.Get(context.Background(), client.ObjectKey{Name: existing.Name}, &actual)
	if actual.Labels[policy.EnrollmentLabel] != "true" {
		t.Fatal("another actor's label removed")
	}
	// A second policy blocks both, and deleting it restores evaluation.
	other := p.DeepCopy()
	other.Name = "other"
	other.ResourceVersion = ""
	if err := c.Create(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), request.NamespacedName, &got)
	if got.Status.Selected != 0 || meta.FindStatusCondition(got.Status.Conditions, "EvaluationReady").Reason != "PolicyConflict" {
		t.Fatal("conflicting policies evaluated")
	}
	if err := c.Delete(context.Background(), other); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	_ = c.Get(context.Background(), request.NamespacedName, &got)
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "EvaluationReady") {
		t.Fatal("policy did not recover")
	}
}
