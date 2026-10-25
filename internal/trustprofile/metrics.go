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
