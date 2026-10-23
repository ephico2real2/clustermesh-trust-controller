package telemetry

import "github.com/prometheus/client_golang/prometheus"

// Metrics exposes intent and inventory only. No Protected/SVID/transport success is inferred.
type Metrics struct {
	Decisions                                *prometheus.GaugeVec
	Eligible, Labeled, Selected, Enforcement prometheus.Gauge
	Evaluations                              prometheus.Counter
	AgentReady                               prometheus.Gauge
	Pods                                     *prometheus.GaugeVec
}

func New(reg prometheus.Registerer, cluster, node string) *Metrics {
	clusterLabels := prometheus.Labels{"cluster": cluster}
	gauge := func(name, help string) prometheus.Gauge {
		return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help, ConstLabels: clusterLabels})
	}
	m := &Metrics{
		Decisions:   prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cmtc_namespace_decisions", Help: "Current namespace policy decisions; selection is intent, not enforcement.", ConstLabels: clusterLabels}, []string{"decision"}),
		Eligible:    gauge("cmtc_namespaces_eligible", "Observed non-platform namespaces, including explicit exclusions."),
		Labeled:     gauge("cmtc_namespaces_enrolled", "Namespaces carrying the enrollment label from any actor; not protection proof."),
		Selected:    gauge("cmtc_namespaces_selected", "Namespaces selected by the current singleton policy; labels are not modified."),
		Enforcement: gauge("cmtc_enforcement_available", "Whether CMTC can verify required datapath enforcement; always zero in Observe mode."),
		Evaluations: prometheus.NewCounter(prometheus.CounterOpts{Name: "cmtc_policy_evaluations_total", Help: "Successful policy evaluations.", ConstLabels: clusterLabels}),
	}
	if node == "" {
		reg.MustRegister(m.Decisions, m.Eligible, m.Labeled, m.Selected, m.Enforcement, m.Evaluations)
	} else {
		m.AgentReady = prometheus.NewGauge(prometheus.GaugeOpts{Name: "cmtc_node_agent_ready", Help: "Successful local inventory observation; not enforcement readiness.", ConstLabels: prometheus.Labels{"cluster": cluster, "node": node}})
		m.Pods = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cmtc_pods_observed", Help: "Observed local pods by network category; not protected pod counts.", ConstLabels: prometheus.Labels{"cluster": cluster, "node": node}}, []string{"network"})
		reg.MustRegister(m.AgentReady, m.Pods)
	}
	return m
}

func (m *Metrics) SetDecisions(counts map[string]int, labeled int) {
	for _, d := range []string{"selected", "excluded", "platform", "unselected"} {
		m.Decisions.WithLabelValues(d).Set(float64(counts[d]))
	}
	m.Eligible.Set(float64(counts["selected"] + counts["excluded"] + counts["unselected"]))
	m.Selected.Set(float64(counts["selected"]))
	m.Labeled.Set(float64(labeled))
	m.Enforcement.Set(0)
}
