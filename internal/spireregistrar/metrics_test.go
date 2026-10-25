package spireregistrar

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func registrarSample(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if len(metric.Label) != len(labels) {
				continue
			}
			matches := true
			for _, label := range metric.Label {
				if labels[label.GetName()] != label.GetValue() {
					matches = false
				}
			}
			if matches {
				if metric.Counter != nil {
					return metric.Counter.GetValue()
				}
				return metric.Gauge.GetValue()
			}
		}
	}
	t.Fatalf("missing expected observed series %s %v", name, labels)
	return 0
}
func requireRegistrarSample(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string, want float64) {
	t.Helper()
	if got := registrarSample(t, reg, name, labels); got != want {
		t.Fatalf("%s %v = %v, want %v", name, labels, got, want)
	}
}
func metricRunner(t *testing.T) (*Runner, *memoryEntries, *prometheus.Registry) {
	t.Helper()
	o, c, _ := fixture(t)
	entries := newEntries()
	r := &Runner{Registrar: Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}, Log: logr.Discard()}
	reg := prometheus.NewRegistry()
	m, err := NewMetrics(reg, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Metrics = m
	r.Registrar.Metrics = m
	return r, entries, reg
}

func TestRegistrarMetricsUnknownCreateACKRetryAndRecovery(t *testing.T) {
	r, entries, reg := metricRunner(t)
	entries.createErr = true
	r.runPass(context.Background(), 1, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "error"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "readback_ack"}, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "error"}, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_withdrawal_attempts_total", map[string]string{"reason": "failure", "result": "acknowledged"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 0)
	if len(entries.rows) != 0 {
		t.Fatal("unknown create acknowledgment retained a row")
	}
	entries.createErr = false
	r.runPass(context.Background(), 2, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "error"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "readback_ack"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 1)
	if len(entries.rows) != 3 {
		t.Fatal("recovery did not run exact production reconciliation")
	}
	r.runPass(context.Background(), 3, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "error"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "readback_ack"}, 2)
}

func TestRegistrarMetricsDuplicateWriterRetainsExactRowsAndRecovers(t *testing.T) {
	r, entries, reg := metricRunner(t)
	r.runPass(context.Background(), 1, time.Now())
	id := string(testUID("foreign-metric-test"))
	entries.rows[id] = &types.Entry{Id: id, Hint: "foreign", SpiffeId: &types.SPIFFEID{TrustDomain: r.Registrar.Source.Options.TrustDomain, Path: "/ns/orders/sa/api"}, ParentId: &types.SPIFFEID{TrustDomain: r.Registrar.Source.Options.TrustDomain, Path: "/foreign"}}
	r.runPass(context.Background(), 2, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "duplicate_writer"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_withdrawal_attempts_total", map[string]string{"reason": "failure", "result": "acknowledged"}, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 0)
	if len(entries.rows) != 4 {
		t.Fatal("duplicate writer changed the exact or foreign rows")
	}
	delete(entries.rows, id)
	r.runPass(context.Background(), 3, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "duplicate_writer"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 1)
}

type retainedMetricDeletion struct{ *memoryEntries }

func (m retainedMetricDeletion) BatchDeleteEntry(_ context.Context, in *entryv1.BatchDeleteEntryRequest, _ ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	return &entryv1.BatchDeleteEntryResponse{Results: []*entryv1.BatchDeleteEntryResponse_Result{{Id: in.Ids[0], Status: &types.Status{Code: int32(codes.OK)}}}}, nil
}

func TestRegistrarMetricsDeleteNeedsACKAndAbsence(t *testing.T) {
	r, entries, reg := metricRunner(t)
	r.runPass(context.Background(), 1, time.Now())
	var id string
	for key := range entries.rows {
		id = key
		break
	}
	r.Registrar.Entries = retainedMetricDeletion{entries}
	if err := r.Registrar.deleteAcknowledged(context.Background(), id); err == nil {
		t.Fatal("delete ACK without absent readback succeeded")
	}
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "error"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "acknowledged_absent"}, 0)
	r.Registrar.Entries = entries
	entries.lostDeleteACK = true
	if err := r.Registrar.deleteAcknowledged(context.Background(), id); err == nil {
		t.Fatal("lost deletion acknowledgment counted success")
	}
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "error"}, 2)
	entries.lostDeleteACK = false
	if err := r.Registrar.Withdraw(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The row deleted under a lost ACK is absent and causes no new delete RPC.
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "acknowledged_absent"}, 2)
}

func TestRegistrarMetricsEnrollmentWithdrawalUsesRealDeleteReadback(t *testing.T) {
	r, entries, reg := metricRunner(t)
	r.runPass(context.Background(), 1, time.Now())
	var namespace corev1.Namespace
	if err := r.Registrar.Source.Reader.Get(context.Background(), client.ObjectKey{Name: "orders"}, &namespace); err != nil {
		t.Fatal(err)
	}
	delete(namespace.Labels, "io.cilium/mtls-enabled")
	writer := r.Registrar.Source.Reader.(client.Client)
	if err := writer.Update(context.Background(), &namespace); err != nil {
		t.Fatal(err)
	}
	r.runPass(context.Background(), 2, time.Now())
	if len(entries.rows) != 2 {
		t.Fatal("normal unenrollment did not remove exactly its workload row")
	}
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "acknowledged_absent"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_withdrawal_attempts_total", map[string]string{"reason": "failure", "result": "acknowledged"}, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "error"}, 0)
}

func TestRegistrarMetricsFreshnessAndProcessReset(t *testing.T) {
	r := &Runner{Log: logr.Discard()}
	now := time.Unix(2000000000, 0)
	reg := prometheus.NewRegistry()
	m, err := newMetrics(reg, r, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	r.Metrics = m
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_timestamp_seconds", nil, 0)
	ack := now
	r.acknowledged.Store(&ack)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 1)
	now = now.Add(21 * time.Second)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_available", nil, 0)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_timestamp_seconds", nil, float64(ack.Unix()))
	r.acknowledged.Store(nil)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_readback_timestamp_seconds", nil, 0)
	_, _, fresh := metricRunner(t)
	requireRegistrarSample(t, fresh, "cmtc_spire_registrar_readback_available", nil, 0)
	requireRegistrarSample(t, fresh, "cmtc_spire_registrar_reconcile_attempts_total", map[string]string{"result": "readback_ack"}, 0)
	if _, err := NewMetrics(reg, r); err == nil {
		t.Fatal("duplicate metric registration succeeded")
	}
}

func TestRegistrarMetricsCanceledRetryAndShutdown(t *testing.T) {
	r, _, reg := metricRunner(t)
	r.retryResult = passError
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.runPass(ctx, 2, time.Now())
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_retries_total", map[string]string{"cause": "error"}, 0)
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_withdrawal_attempts_total", map[string]string{"reason": "shutdown", "result": "acknowledged"}, 1)
	requireRegistrarSample(t, reg, "cmtc_spire_registrar_entry_deletion_attempts_total", map[string]string{"result": "acknowledged_absent"}, 0)
}

func TestRegistrarMetricsLabelsAreCodeOwned(t *testing.T) {
	r, _, reg := metricRunner(t)
	r.Metrics.completed(passResult(255))
	r.Metrics.retried(passResult(255))
	r.Metrics.withdrew(withdrawalReason(255), nil)
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"readback_ack": true, "error": true, "duplicate_writer": true, "failure": true, "shutdown": true, "acknowledged": true, "acknowledged_absent": true}
	series := 0
	for _, family := range families {
		for _, metric := range family.Metric {
			series++
			for _, label := range metric.Label {
				if label.GetName() != "result" && label.GetName() != "cause" && label.GetName() != "reason" {
					t.Fatal("unbounded label name")
				}
				if !allowed[label.GetValue()] {
					t.Fatal("unbounded label value")
				}
			}
		}
	}
	if series != 13 {
		t.Fatalf("series=%d, want 13 fixed initialized series", series)
	}
}
