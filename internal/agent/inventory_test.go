package agent

import (
	"context"
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestInventoryIsNodeScopedAndNeverProtection(t *testing.T) {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	c := fake.NewClientBuilder().WithScheme(s).WithIndex(&corev1.Pod{}, "spec.nodeName", func(o client.Object) []string { return []string{o.(*corev1.Pod).Spec.NodeName} }).WithObjects(
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "local", Namespace: "app"}, Spec: corev1.PodSpec{NodeName: "a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "host", Namespace: "system"}, Spec: corev1.PodSpec{NodeName: "a", HostNetwork: true}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "remote", Namespace: "app"}, Spec: corev1.PodSpec{NodeName: "b"}},
	).Build()
	reg := prometheus.NewRegistry()
	m := telemetry.New(reg, "test", "a")
	a := Inventory{Client: c, Node: "a", Metrics: m}
	if err := a.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if testutil.ToFloat64(m.Pods.WithLabelValues("pod")) != 1 || testutil.ToFloat64(m.Pods.WithLabelValues("host")) != 1 {
		t.Fatal("remote pods counted or hostNetwork conflated")
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() == "cmtc_pods_protected" {
			t.Fatal("inventory exported protection")
		}
	}
}
