package trustprofile

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Counters count this producer process's attempts/acknowledgments, not globally
// unique incidents or consumer readiness. No source UID/domain/key is a label.
type Metrics struct {
	Validation     *prometheus.CounterVec
	Writes         *prometheus.CounterVec
	SourceChecked  prometheus.Gauge
	PublishedUntil prometheus.Gauge
}

func NewMetrics(reg prometheus.Registerer, cluster string) (*Metrics, error) {
	labels := prometheus.Labels{"cluster": cluster}
	m := &Metrics{
		Validation:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_issuer_profile_validation_attempts_total", Help: "Source validation attempts including retries; not trust consumption or traffic enforcement.", ConstLabels: labels}, []string{"result"}),
		Writes:         prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_issuer_profile_publication_writes_total", Help: "Output API write responses by state and acknowledged/error result; not exact globally unique publications.", ConstLabels: labels}, []string{"state", "result"}),
		SourceChecked:  prometheus.NewGauge(prometheus.GaugeOpts{Name: "cmtc_issuer_profile_source_checked_timestamp_seconds", Help: "Last successful uncached source API read timestamp, whether or not validation succeeded.", ConstLabels: labels}),
		PublishedUntil: prometheus.NewGauge(prometheus.GaugeOpts{Name: "cmtc_issuer_profile_acknowledged_valid_until_timestamp_seconds", Help: "Last API-acknowledged local publication lease expiry, zero after acknowledged withdrawal; not consumer readiness.", ConstLabels: labels}),
	}
	for _, c := range []prometheus.Collector{m.Validation, m.Writes, m.SourceChecked, m.PublishedUntil} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// ArbiterMetrics describe the approval arbiter's passes and the node reports it read (ADR-012). Labels are bounded:
// phases and results are fixed sets, report_cluster is a configured cluster name.
type ArbiterMetrics struct {
	Generation *prometheus.GaugeVec
	Expiry     prometheus.Gauge
	Phase      *prometheus.GaugeVec
	Passes     *prometheus.CounterVec
	Reports    *prometheus.GaugeVec
}

func NewArbiterMetrics(reg prometheus.Registerer, cluster string) (*ArbiterMetrics, error) {
	labels := prometheus.Labels{"cluster": cluster}
	m := &ArbiterMetrics{
		Generation: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cmtc_issuer_approval_generation", Help: "Approval generation by role: accepted (named by the publication) or pending (written, not yet published).", ConstLabels: labels}, []string{"role"}),
		Expiry:     prometheus.NewGauge(prometheus.GaugeOpts{Name: "cmtc_issuer_approval_expiry_timestamp_seconds", Help: "Expiry of the accepted approval; zero when there is none.", ConstLabels: labels}),
		Phase:      prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cmtc_issuer_approval_phase", Help: "1 for the arbiter's current phase, 0 for the others.", ConstLabels: labels}, []string{"phase"}),
		Passes:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "cmtc_issuer_approval_passes_total", Help: "Arbiter passes by result: wrote, deleted, held, idle or error.", ConstLabels: labels}, []string{"result"}),
		Reports:    prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cmtc_issuer_approval_node_reports", Help: "Nodes of a cluster by report state at the last pass that read them: fresh, stale, missing; accepting counts local nodes that accept the accepted generation.", ConstLabels: labels}, []string{"report_cluster", "state"}),
	}
	for _, c := range []prometheus.Collector{m.Generation, m.Expiry, m.Phase, m.Passes, m.Reports} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	return m, nil
}
