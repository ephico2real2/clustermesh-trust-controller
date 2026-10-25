package spireregistrar

import (
	"errors"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type passResult uint8

const (
	passReadbackACK passResult = iota
	passError
	passDuplicateWriter
)

type withdrawalReason uint8

const (
	withdrawalFailure withdrawalReason = iota
	withdrawalShutdown
)

// Metrics describes this registrar process's observations, not agent readiness,
// certificate issuance/revocation, TLS, policy enforcement or Protected status.
// Cluster/node/instance are discovery/scrape labels, not workload label values.
type Metrics struct {
	passes            *prometheus.CounterVec
	retries           *prometheus.CounterVec
	withdrawals       *prometheus.CounterVec
	deletions         *prometheus.CounterVec
	available         prometheus.GaugeFunc
	readbackTimestamp prometheus.GaugeFunc
}

func NewMetrics(reg prometheus.Registerer, runner *Runner) (*Metrics, error) {
	return newMetrics(reg, runner, time.Now)
}

func newMetrics(reg prometheus.Registerer, runner *Runner, now func() time.Time) (*Metrics, error) {
	if reg == nil || runner == nil || now == nil {
		return nil, errors.New("registrar metrics requires registry, runner and clock")
	}
	m := &Metrics{
		passes:      prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_spire_registrar_reconcile_attempts_total", Help: "Completed registrar passes by result; one final readback_ack or error outcome per pass, including retries."}, []string{"result"}),
		retries:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_spire_registrar_retries_total", Help: "Actual next registrar passes after failure; successful periodic refreshes and canceled scheduled retries do not count."}, []string{"cause"}),
		withdrawals: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_spire_registrar_withdrawal_attempts_total", Help: "Whole owned-inventory withdrawal calls by trigger and result; empty inventory may succeed; not certificate revocation."}, []string{"reason", "result"}),
		deletions:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_spire_registrar_entry_deletion_attempts_total", Help: "Actual BatchDeleteEntry calls; acknowledged_absent requires explicit deletion response plus GetEntry NotFound; errors can follow a committed delete."}, []string{"result"}),
	}
	m.available = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "cmtc_spire_registrar_readback_available", Help: "One only while this process has a successful complete exact registration readback at most 20 seconds old and no later pass failure; not SPIRE or workload readiness."}, func() float64 {
		if runner.readbackCurrent(now()) {
			return 1
		}
		return 0
	})
	m.readbackTimestamp = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "cmtc_spire_registrar_readback_timestamp_seconds", Help: "Timestamp of this process's current complete successful readback; zero before success or after failure/shutdown; may be stale, so check readback_available."}, func() float64 {
		last := runner.acknowledged.Load()
		if last == nil {
			return 0
		}
		return float64(last.UnixNano()) / 1e9
	})
	for _, result := range []string{"readback_ack", "error", "duplicate_writer"} {
		m.passes.WithLabelValues(result)
	}
	for _, cause := range []string{"error", "duplicate_writer"} {
		m.retries.WithLabelValues(cause)
	}
	for _, reason := range []string{"failure", "shutdown"} {
		for _, result := range []string{"acknowledged", "error"} {
			m.withdrawals.WithLabelValues(reason, result)
		}
	}
	for _, result := range []string{"acknowledged_absent", "error"} {
		m.deletions.WithLabelValues(result)
	}
	// Register the aggregate once: duplicate registration cannot leave a prefix
	// of the metric set installed in the registry.
	if err := reg.Register(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{m.passes, m.retries, m.withdrawals, m.deletions, m.available, m.readbackTimestamp}
}
func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	for _, collector := range m.collectors() {
		collector.Describe(ch)
	}
}
func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	for _, collector := range m.collectors() {
		collector.Collect(ch)
	}
}

func passLabel(result passResult) string {
	switch result {
	case passReadbackACK:
		return "readback_ack"
	case passError:
		return "error"
	case passDuplicateWriter:
		return "duplicate_writer"
	}
	return ""
}
func (m *Metrics) completed(result passResult) {
	if m == nil {
		return
	}
	if label := passLabel(result); label != "" {
		m.passes.WithLabelValues(label).Inc()
	}
}
func (m *Metrics) retried(result passResult) {
	if m == nil || result == passReadbackACK {
		return
	}
	if label := passLabel(result); label != "" {
		m.retries.WithLabelValues(label).Inc()
	}
}
func (m *Metrics) withdrew(reason withdrawalReason, err error) {
	if m == nil {
		return
	}
	var label string
	switch reason {
	case withdrawalFailure:
		label = "failure"
	case withdrawalShutdown:
		label = "shutdown"
	default:
		return
	}
	result := "acknowledged"
	if err != nil {
		result = "error"
	}
	m.withdrawals.WithLabelValues(label, result).Inc()
}
func (m *Metrics) deleted(err error) {
	if m == nil {
		return
	}
	result := "acknowledged_absent"
	if err != nil {
		result = "error"
	}
	m.deletions.WithLabelValues(result).Inc()
}
