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
	Metrics      *Metrics
	retryResult  passResult
	acknowledged atomic.Pointer[time.Time]
}

var _ manager.Runnable = (*Runner)(nil)

func (*Runner) NeedLeaderElection() bool { return false }
func (r *Runner) readbackCurrent(now time.Time) bool {
	last := r.acknowledged.Load()
	return last != nil && !now.Before(*last) && now.Sub(*last) <= 20*time.Second
}
func (r *Runner) Ready(*http.Request) error {
	if !r.readbackCurrent(time.Now()) {
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
		r.runPass(ctx, attempt, time.Now())
		delay := 10 * time.Second
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
	if err := r.withdraw(cleanup, withdrawalShutdown); err != nil {
		r.Log.Error(err, "SPIRE registrar shutdown withdrawal failed; owned entries retain bounded expiry", "stage", "shutdown-withdraw")
	}
	return nil
}

func (r *Runner) noteFailure(err error, attempt int, started time.Time) {
	r.acknowledged.Store(nil)
	delay := 10 * time.Second
	var duplicate *DuplicateWriterError
	if errors.As(err, &duplicate) {
		// Keep the stricter exact rows. Deleting them would leave the foreign
		// entitlement as the only registration for that SPIFFE ID.
		r.Log.Error(err, "SPIRE exact registration refused a second writer", "component", "spire-registrar", "stage", "duplicate-writer", "attempt", attempt, "elapsed", time.Since(started), "nextRetry", delay, "deadline", 20*time.Second)
		return
	}
	// Use a new bounded context: a failed/canceled API request cannot skip
	// best-effort removal of already acknowledged or ambiguously created rows.
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	cleanupErr := r.withdraw(cleanup, withdrawalFailure)
	stop()
	r.Log.Error(errors.Join(err, cleanupErr), "SPIRE exact registration pass failed", "component", "spire-registrar", "stage", "reconcile-withdraw", "attempt", attempt, "elapsed", time.Since(started), "nextRetry", delay, "deadline", 20*time.Second)
}

// runPass is also the deterministic test seam. Production still owns the real
// 20s request bound, 10s timer and 5s failure/shutdown cleanup budgets.
func (r *Runner) runPass(ctx context.Context, attempt int, start time.Time) {
	if ctx.Err() != nil {
		return
	}
	if r.retryResult != passReadbackACK {
		r.Metrics.retried(r.retryResult)
	}
	pass, cancel := context.WithTimeout(ctx, 20*time.Second)
	count, err := r.Registrar.Reconcile(pass, start)
	cancel()
	result := passReadbackACK
	if err != nil {
		result = passError
		var duplicate *DuplicateWriterError
		if errors.As(err, &duplicate) {
			result = passDuplicateWriter
		}
		r.noteFailure(err, attempt, start)
	} else {
		now := time.Now()
		r.acknowledged.Store(&now)
		r.Log.Info("SPIRE exact registration rows acknowledged", "component", "spire-registrar", "stage", "readback-ack", "attempt", attempt, "elapsed", time.Since(start), "entries", count, "nextRetry", 10*time.Second, "deadline", 20*time.Second)
	}
	r.retryResult = result
	r.Metrics.completed(result)
}

func (r *Runner) withdraw(ctx context.Context, reason withdrawalReason) (err error) {
	defer func() { r.Metrics.withdrew(reason, err) }()
	return r.Registrar.Withdraw(ctx)
}
