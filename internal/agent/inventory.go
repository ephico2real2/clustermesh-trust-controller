package agent

import (
	"context"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Inventory struct {
	Client  client.Reader
	Node    string
	Metrics *telemetry.Metrics
}

func (a *Inventory) Observe(ctx context.Context) error {
	var pods corev1.PodList
	if err := a.Client.List(ctx, &pods, client.MatchingFields{"spec.nodeName": a.Node}); err != nil {
		a.Metrics.AgentReady.Set(0)
		return err
	}
	counts := map[string]int{"pod": 0, "host": 0}
	for _, p := range pods.Items {
		if p.Spec.HostNetwork {
			counts["host"]++
		} else {
			counts["pod"]++
		}
	}
	for key, value := range counts {
		a.Metrics.Pods.WithLabelValues(key).Set(float64(value))
	}
	a.Metrics.AgentReady.Set(1)
	return nil
}

func (a *Inventory) Start(ctx context.Context) error {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		// Inventory failure is observable and retried, never interpreted as zero protected pods.
		_ = a.Observe(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (a *Inventory) NeedLeaderElection() bool { return false }
