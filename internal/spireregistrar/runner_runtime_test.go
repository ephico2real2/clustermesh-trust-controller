package spireregistrar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// All fake RPC state has a lock because readiness/log assertions run while the
// actual production runner is active. No retry duration or clock is replaced.
type runnerEntries struct {
	entryv1.EntryClient
	mu                    sync.Mutex
	inner                 *memoryEntries
	getCalls, deleteCalls int
	barrierStarted        chan struct{}
	barrierRelease        chan struct{}
	barrierUsed           bool
}

func (m *runnerEntries) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.inner.rows) }
func (m *runnerEntries) holdNextReadback() (<-chan struct{}, chan<- struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.barrierStarted = make(chan struct{})
	m.barrierRelease = make(chan struct{})
	m.barrierUsed = false
	return m.barrierStarted, m.barrierRelease
}
func (m *runnerEntries) ListEntries(ctx context.Context, in *entryv1.ListEntriesRequest, opts ...grpc.CallOption) (*entryv1.ListEntriesResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.ListEntries(ctx, in, opts...)
}
func (m *runnerEntries) GetEntry(ctx context.Context, in *entryv1.GetEntryRequest, opts ...grpc.CallOption) (*types.Entry, error) {
	m.mu.Lock()
	m.getCalls++
	result, err := m.inner.GetEntry(ctx, in, opts...)
	var release <-chan struct{}
	if err == nil && m.barrierStarted != nil && !m.barrierUsed {
		m.barrierUsed = true
		close(m.barrierStarted)
		release = m.barrierRelease
	}
	m.mu.Unlock()
	if release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
	}
	return result, err
}
func (m *runnerEntries) BatchCreateEntry(ctx context.Context, in *entryv1.BatchCreateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchCreateEntryResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.BatchCreateEntry(ctx, in, opts...)
}
func (m *runnerEntries) BatchUpdateEntry(ctx context.Context, in *entryv1.BatchUpdateEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchUpdateEntryResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inner.BatchUpdateEntry(ctx, in, opts...)
}
func (m *runnerEntries) BatchDeleteEntry(ctx context.Context, in *entryv1.BatchDeleteEntryRequest, opts ...grpc.CallOption) (*entryv1.BatchDeleteEntryResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deleteCalls++
	return m.inner.BatchDeleteEntry(ctx, in, opts...)
}

type runnerFaultReader struct {
	client.Reader
	mu             sync.Mutex
	available      bool
	successfulGets int
}

func (r *runnerFaultReader) enable()   { r.mu.Lock(); r.available = true; r.mu.Unlock() }
func (r *runnerFaultReader) gets() int { r.mu.Lock(); defer r.mu.Unlock(); return r.successfulGets }
func (r *runnerFaultReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.mu.Lock()
	available := r.available
	r.mu.Unlock()
	if !available {
		return errors.New("test Kubernetes API temporarily unavailable")
	}
	err := r.Reader.Get(ctx, key, obj, opts...)
	if err == nil {
		r.mu.Lock()
		r.successfulGets++
		r.mu.Unlock()
	}
	return err
}

type runnerLogEvent struct {
	at      time.Time
	message string
	err     error
	fields  map[string]any
}
type runnerLogCapture struct {
	mu     sync.Mutex
	events []runnerLogEvent
	notify chan runnerLogEvent
}
type runnerLogSink struct {
	capture *runnerLogCapture
	values  []any
	name    string
}

func (*runnerLogSink) Init(logr.RuntimeInfo) {}
func (*runnerLogSink) Enabled(int) bool      { return true }
func (s *runnerLogSink) record(message string, err error, args ...any) {
	fields := map[string]any{}
	all := append(append([]any(nil), s.values...), args...)
	for i := 0; i+1 < len(all); i += 2 {
		if key, ok := all[i].(string); ok {
			fields[key] = all[i+1]
		}
	}
	event := runnerLogEvent{at: time.Now(), message: message, err: err, fields: fields}
	s.capture.mu.Lock()
	s.capture.events = append(s.capture.events, event)
	s.capture.mu.Unlock()
	s.capture.notify <- event
}
func (s *runnerLogSink) Info(_ int, message string, args ...any) { s.record(message, nil, args...) }
func (s *runnerLogSink) Error(err error, message string, args ...any) {
	s.record(message, err, args...)
}
func (s *runnerLogSink) WithValues(args ...any) logr.LogSink {
	return &runnerLogSink{capture: s.capture, values: append(append([]any(nil), s.values...), args...), name: s.name}
}
func (s *runnerLogSink) WithName(name string) logr.LogSink {
	return &runnerLogSink{capture: s.capture, values: append([]any(nil), s.values...), name: s.name + "/" + name}
}

func TestRunnerActualRetryReadbackReadinessAndShutdown(t *testing.T) {
	o, c, _ := fixture(t)
	entries := &runnerEntries{inner: newEntries()}
	registrar := Registrar{Source: Source{Reader: c, Options: o}, Entries: entries}
	if _, err := registrar.Reconcile(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if entries.count() != 3 {
		t.Fatal("retained-row setup failed")
	}
	// A new process cannot infer current readiness from retained SPIRE rows.
	api := &runnerFaultReader{Reader: c}
	registrar.Source.Reader = api
	logs := &runnerLogCapture{notify: make(chan runnerLogEvent, 16)}
	runner := &Runner{Registrar: registrar, Log: logr.New(&runnerLogSink{capture: logs})}
	if runner.Ready(nil) == nil {
		t.Fatal("startup restored readiness from retained rows")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	done := make(chan struct{})
	var runErr error
	go func() { runErr = runner.Start(ctx); close(done) }()
	// Always join the real runner even if a test assertion fails.
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("runner failed to stop during test cleanup")
		}
	}()
	var failed runnerLogEvent
	select {
	case failed = <-logs.notify:
	case <-ctx.Done():
		t.Fatal("initial failing pass did not log")
	}
	if failed.err == nil || failed.fields["stage"] != "reconcile-withdraw" || failed.fields["attempt"] != 1 || failed.fields["nextRetry"] != 10*time.Second || failed.fields["deadline"] != 20*time.Second {
		t.Fatalf("missing structured retry/deadline/error fields: %+v", failed)
	}
	if _, ok := failed.fields["elapsed"].(time.Duration); !ok {
		t.Fatal("retry log omitted elapsed duration")
	}
	if runner.Ready(nil) == nil || entries.count() != 0 {
		t.Fatal("API failure kept readiness or retained entitlements")
	}
	// Hold the actual positive GetEntry readback on attempt two. Merely
	// restoring the API or creating an entry must not open readiness early.
	started, release := entries.holdNextReadback()
	api.enable()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("actual scheduled retry never reached fresh readback")
	}
	if api.gets() == 0 || runner.Ready(nil) == nil {
		t.Fatal("retry bypassed fresh API or readback readiness barrier")
	}
	close(release)
	var accepted runnerLogEvent
	select {
	case accepted = <-logs.notify:
	case <-ctx.Done():
		t.Fatal("positive readback was not acknowledged")
	}
	if accepted.err != nil || accepted.fields["stage"] != "readback-ack" || accepted.fields["attempt"] != 2 || accepted.fields["entries"] != 3 {
		t.Fatalf("fresh registration ACK log mismatch: %+v", accepted)
	}
	if accepted.at.Sub(failed.at) < 10*time.Second {
		t.Fatalf("production 10s retry was bypassed: %s", accepted.at.Sub(failed.at))
	}
	if runner.Ready(nil) != nil || entries.count() != 3 {
		t.Fatal("fresh exact readback did not open registration readiness")
	}
	cancel()
	select {
	case <-done:
		if runErr != nil {
			t.Fatal(runErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not stop the real retry loop")
	}
	if runner.Ready(nil) == nil || entries.count() != 0 {
		t.Fatal("shutdown retained readiness or SPIRE rows")
	}
	entries.mu.Lock()
	defer entries.mu.Unlock()
	if entries.deleteCalls != 6 || entries.getCalls < 12 {
		t.Fatalf("missing verified startup/shutdown removals: deletes=%d gets=%d", entries.deleteCalls, entries.getCalls)
	}
}
