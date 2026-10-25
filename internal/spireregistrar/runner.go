package spireregistrar

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

type Runner struct {
	Registrar    Registrar
	Log          logr.Logger
	acknowledged atomic.Pointer[time.Time]
}

var _ manager.Runnable = (*Runner)(nil)

func (*Runner) NeedLeaderElection() bool { return false }
func (r *Runner) Ready(*http.Request) error {
	last := r.acknowledged.Load()
	if last == nil || time.Since(*last) > 20*time.Second {
		return errors.New("exact SPIRE registration readback is unavailable or stale")
	}
	return nil
}
func (r *Runner) Start(ctx context.Context) error {
	attempt := 0
	for {
		if ctx.Err() != nil {
			break
		}
		attempt++
		start := time.Now()
		pass, cancel := context.WithTimeout(ctx, 20*time.Second)
		count, err := r.Registrar.Reconcile(pass, start)
		cancel()
		delay := 10 * time.Second
		if err != nil {
			r.acknowledged.Store(nil)
			// Use a new bounded context: a failed/canceled API request cannot skip
			// best-effort removal of already acknowledged or ambiguously created rows.
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			cleanupErr := r.Registrar.Withdraw(cleanup)
			stop()
			r.Log.Error(errors.Join(err, cleanupErr), "SPIRE exact registration pass failed", "component", "spire-registrar", "stage", "reconcile-withdraw", "attempt", attempt, "elapsed", time.Since(start), "nextRetry", delay, "deadline", 20*time.Second)
		} else {
			now := time.Now()
			r.acknowledged.Store(&now)
			r.Log.Info("SPIRE exact registration rows acknowledged", "component", "spire-registrar", "stage", "readback-ack", "attempt", attempt, "elapsed", time.Since(start), "entries", count, "nextRetry", delay, "deadline", 20*time.Second)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	r.acknowledged.Store(nil)
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Registrar.Withdraw(cleanup); err != nil {
		r.Log.Error(err, "SPIRE registrar shutdown withdrawal failed; owned entries retain bounded expiry", "stage", "shutdown-withdraw")
	}
	return nil
}
