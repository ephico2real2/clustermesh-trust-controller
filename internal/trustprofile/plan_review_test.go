package trustprofile

import (
	"strings"
	"testing"
	"time"
)

// SPIRE may run with a ca_ttl the arbiter cannot read (server.conf states it in a form the arbiter does not parse), and
// that ca_ttl can be longer than the bound recorded earlier. An unknown reading on the retirement pass therefore holds
// the old key; the next known reading retires it.
func TestUnknownCATTLHoldsRetirementAfterAKnownBound(t *testing.T) {
	m := newMesh(t)
	oldKey := m.intermediates["cmtc-a"]
	b := func(at time.Time) Evidence { return evidenceFor(t, m, "cmtc-b", m.intermediates["cmtc-b"], at) }
	boot := mustPlan(t, planInput(t, m, planNow, nil, nil, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", oldKey, planNow), "cmtc-b": b(planNow)}))
	first := validated(t, m, boot.Next, planNow).Approval
	switched := planNow.Add(time.Minute)
	newKey := m.intermediate(t, "cmtc-a", switched, switched.AddDate(1, 0, 0))
	rotation := mustPlan(t, planInput(t, m, switched, &first, boot.Ledger, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, switched), "cmtc-b": b(switched)}))
	if rotation.Next == nil || rotation.Reason != ReasonIssuerAdded {
		t.Fatalf("rotation: %+v %s", rotation.Next, holdReasons(rotation))
	}
	overlap := validated(t, m, rotation.Next, switched).Approval
	retireAt := switched.Add(48*time.Hour + time.Hour)
	unknown := evidenceFor(t, m, "cmtc-a", newKey, retireAt)
	unknown.SPIRECAMaxDuration = 0
	held := mustPlan(t, planInput(t, m, retireAt, &overlap, rotation.Ledger, map[string]Evidence{"cmtc-a": unknown, "cmtc-b": b(retireAt)}))
	if held.Next != nil || !strings.Contains(holdReasons(held), "cmtc-a:"+HoldRetirementWaiting) {
		t.Fatalf("retired on the earlier 48h bound while ca_ttl is unreadable: %+v %s", held.Next, holdReasons(held))
	}
	retire := mustPlan(t, planInput(t, m, retireAt, &overlap, held.Ledger, map[string]Evidence{"cmtc-a": evidenceFor(t, m, "cmtc-a", newKey, retireAt), "cmtc-b": b(retireAt)}))
	if retire.Next == nil || retire.Reason != ReasonIssuerRetired || strings.Join(issuerKeys(retire.Next, "cmtc-a"), ",") != spki(newKey) {
		t.Fatalf("a known ca_ttl did not retire the old key: %+v %s", retire.Next, holdReasons(retire))
	}
}
