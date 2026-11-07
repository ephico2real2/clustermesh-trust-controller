package measurement

import (
	"testing"
	"time"
)

func queries(n uint64) PodCounters {
	var c PodCounters
	c.DNSQueries[0][2] = n
	return c
}

// A namespace's total only grows while its Pods come and go: each attachment adds what it counted since its last
// reading, and a new attachment of the same Pod starts from zero.
func TestAccumulatorKeepsNamespaceTotalsGrowing(t *testing.T) {
	a := NewAccumulator()
	now := time.Now()
	if err := a.Observe(1, "shop", queries(3), now); err != nil {
		t.Fatal(err)
	}
	if err := a.Observe(2, "shop", queries(4), now); err != nil {
		t.Fatal(err)
	}
	if err := a.Observe(1, "shop", queries(5), now); err != nil {
		t.Fatal(err)
	}
	if got := a.Totals()["shop"].DNSQueries[0][2]; got != 9 {
		t.Fatalf("total %d, want 5 + 4", got)
	}

	// Attachment 1 is retired, and its Pod is attached again as attachment 3, whose arrays start at zero.
	a.Release(1)
	if err := a.Observe(3, "shop", queries(1), now); err != nil {
		t.Fatal(err)
	}
	if got := a.Totals()["shop"].DNSQueries[0][2]; got != 10 {
		t.Fatalf("total %d after the new attachment, want 10", got)
	}

	if err := a.Observe(2, "shop", queries(2), now); err == nil {
		t.Fatal("a reading lower than the last one was accepted")
	}
	if got := a.Totals()["shop"].DNSQueries[0][2]; got != 10 {
		t.Fatalf("total %d after the refused reading, want 10", got)
	}
}

func TestAccumulatorPrunesNamespacesAfterRetention(t *testing.T) {
	a := NewAccumulator()
	start := time.Now()
	if err := a.Observe(1, "old", queries(1), start); err != nil {
		t.Fatal(err)
	}
	if err := a.Observe(2, "live", queries(1), start.Add(NamespaceRetention)); err != nil {
		t.Fatal(err)
	}
	a.Prune(start.Add(NamespaceRetention), NamespaceRetention)
	if _, ok := a.Totals()["old"]; !ok {
		t.Fatal("a namespace was pruned at exactly the retention")
	}
	a.Prune(start.Add(NamespaceRetention+time.Second), NamespaceRetention)
	totals := a.Totals()
	if _, ok := totals["old"]; ok {
		t.Fatal("a namespace unseen for longer than the retention was kept")
	}
	if _, ok := totals["live"]; !ok {
		t.Fatal("a namespace seen within the retention was pruned")
	}
}
