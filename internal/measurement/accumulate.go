package measurement

import (
	"fmt"
	"time"
)

// Accumulator turns the counters of each attachment (one Pod's copy of the programs, with arrays of its own) into
// per-namespace counters that only increase while Pods come and go. It is not safe for concurrent use.
type Accumulator struct {
	last       map[uint64]PodCounters // the last reading of each attachment, by attachment ID
	namespaces map[string]*namespaceTotal
}

type namespaceTotal struct {
	counters PodCounters
	lastSeen time.Time
}

// NewAccumulator returns an empty accumulator.
func NewAccumulator() *Accumulator {
	return &Accumulator{last: map[uint64]PodCounters{}, namespaces: map[string]*namespaceTotal{}}
}

// Observe adds the growth of one attachment's counters since its last reading to its namespace. The arrays of an
// attachment only grow, so a decrease means a wrong reading, which is refused.
func (a *Accumulator) Observe(id uint64, namespace string, current PodCounters, now time.Time) error {
	delta, ok := current.Delta(a.last[id])
	if !ok {
		return fmt.Errorf("counters of attachment %d decreased", id)
	}
	t := a.namespaces[namespace]
	if t == nil {
		t = &namespaceTotal{}
		a.namespaces[namespace] = t
	}
	t.counters.Add(delta)
	t.lastSeen = now
	a.last[id] = current
	return nil
}

// Release forgets an attachment after its final reading.
func (a *Accumulator) Release(id uint64) {
	delete(a.last, id)
}

// Prune drops the namespaces that no attachment has observed for retention.
func (a *Accumulator) Prune(now time.Time, retention time.Duration) {
	for ns, t := range a.namespaces {
		if now.Sub(t.lastSeen) > retention {
			delete(a.namespaces, ns)
		}
	}
}

// Totals returns a copy of the per-namespace counters.
func (a *Accumulator) Totals() map[string]PodCounters {
	out := make(map[string]PodCounters, len(a.namespaces))
	for ns, t := range a.namespaces {
		out[ns] = t.counters
	}
	return out
}
