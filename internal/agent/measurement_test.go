package agent

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/measurement"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	uidRunning     = "00000000-0000-4000-8000-000000000001"
	uidPending     = "00000000-0000-4000-8000-000000000002"
	uidTerminating = "00000000-0000-4000-8000-000000000003"
)

func pod(name, namespace, node, uid string, phase corev1.PodPhase, ips ...string) corev1.Pod {
	p := corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, UID: types.UID(uid)},
		Spec: corev1.PodSpec{NodeName: node}, Status: corev1.PodStatus{Phase: phase}}
	for _, ip := range ips {
		p.Status.PodIPs = append(p.Status.PodIPs, corev1.PodIP{IP: ip})
	}
	return p
}

func measuredPods() []corev1.Pod {
	terminating := pod("old", "shop", "a", uidTerminating, corev1.PodRunning, "10.0.0.3")
	now := metav1.Now()
	terminating.DeletionTimestamp = &now
	host := pod("host", "shop", "a", "00000000-0000-4000-8000-000000000004", corev1.PodRunning, "172.18.0.2")
	host.Spec.HostNetwork = true
	return []corev1.Pod{
		pod("web", "shop", "a", uidRunning, corev1.PodRunning, "10.0.0.1", "fd00::1"),
		pod("new", "shop", "a", uidPending, corev1.PodPending),
		terminating,
		host,
		pod("done", "shop", "a", "00000000-0000-4000-8000-000000000005", corev1.PodSucceeded, "10.0.0.5"),
		pod("dns", "kube-system", "a", "00000000-0000-4000-8000-000000000006", corev1.PodRunning, "10.0.0.6"),
		pod("remote", "shop", "b", "00000000-0000-4000-8000-000000000007", corev1.PodRunning, "10.0.1.7"),
	}
}

// The measured Pods are this node's Pending and Running Pods of enrolled namespaces in the Pod network. Only a
// Running Pod that is not terminating is required.
func TestDesiredPods(t *testing.T) {
	got := DesiredPods(measuredPods(), "a", map[string]bool{"shop": true})
	want := []measurement.DesiredPod{
		{UID: uidRunning, Namespace: "shop", Required: true},
		{UID: uidPending, Namespace: "shop"},
		{UID: uidTerminating, Namespace: "shop"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("desired %+v\nwant %+v", got, want)
	}
	if got := DesiredPods(measuredPods(), "a", map[string]bool{}); len(got) != 0 {
		t.Fatalf("Pods %+v measured without an enrolled namespace", got)
	}
}

// Every Pending or Running Pod of the node gives its addresses, enrolled or not, hostNetwork included.
func TestNodeAddresses(t *testing.T) {
	pods := append(measuredPods(), pod("mapped", "kube-system", "a", "00000000-0000-4000-8000-000000000008",
		corev1.PodRunning, "::ffff:10.0.0.1", "not-an-ip"))
	got := NodeAddresses(pods, "a")
	want := []string{"10.0.0.1", "10.0.0.3", "10.0.0.6", "172.18.0.2", "fd00::1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("addresses %v, want %v", got, want)
	}
}

func TestMeasurementSyncWritesTheDesiredListWhenItChanges(t *testing.T) {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	enrolled := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "shop",
		Labels: map[string]string{measurement.EnrollmentLabel: "true"}}}
	web := pod("web", "shop", "a", uidRunning, corev1.PodRunning, "10.0.0.1")
	c := fake.NewClientBuilder().WithScheme(s).WithObjects(enrolled, &web).Build()
	dir := t.TempDir()
	m := &Measurement{Client: c, Node: "a", DesiredDir: dir, Log: logr.Discard(), Interval: time.Second,
		Collector: measurement.NewCollector("cmtc-a", "a", filepath.Join(t.TempDir(), measurement.SnapshotFile),
			measurement.SystemClock())}
	ctx := context.Background()
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, measurement.DesiredFile)
	d, err := measurement.ReadDesired(path)
	if err != nil {
		t.Fatal(err)
	}
	if d.Node != "a" || len(d.Pods) != 1 || d.Pods[0].UID != uidRunning || !reflect.DeepEqual(d.NodeAddresses, []string{"10.0.0.1"}) {
		t.Fatalf("desired %+v", d)
	}

	// Unchanged: the file is not written again.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ModTime().Equal(time.Unix(1, 0)) || after.Size() != before.Size() {
		t.Fatal("an unchanged desired list was written again")
	}

	// A new Pod changes the list.
	added := pod("api", "shop", "a", uidPending, corev1.PodPending)
	if err := c.Create(ctx, &added); err != nil {
		t.Fatal(err)
	}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if d, err = measurement.ReadDesired(path); err != nil || len(d.Pods) != 2 {
		t.Fatalf("desired %+v after a new Pod, error %v", d, err)
	}
}

// A list that fails reaches the collector, which then reports the plane not ready with that reason.
func TestMeasurementSyncReportsAListError(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(runtime.NewScheme()).Build() // no core types: every List fails
	m := &Measurement{Client: c, Node: "a", DesiredDir: t.TempDir(), Log: logr.Discard(), Interval: time.Second,
		Collector: measurement.NewCollector("cmtc-a", "a", filepath.Join(t.TempDir(), measurement.SnapshotFile),
			measurement.SystemClock())}
	if err := m.Sync(context.Background()); err == nil {
		t.Fatal("Sync succeeded without the Namespace type")
	}
	if _, _, ready, reason := m.Collector.Evaluate(); ready || reason == "" {
		t.Fatalf("Evaluate = %v %q, want not ready with the list error", ready, reason)
	}
}
