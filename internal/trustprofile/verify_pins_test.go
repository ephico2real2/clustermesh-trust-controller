package trustprofile

import "testing"

// VerifyCurrent must fail closed on incomplete consumer pins.
func TestVerifyCurrentFailsClosedOnIncompletePins(t *testing.T) {
	a, pins, now := approvalFixture(t)
	a.Generation = 2
	g2, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	p := publicationFor(g2, now)
	p.Sequence = 2
	p.ExpectedSourceUID, p.AcceptedSourceUID = "source-v2", "source-v2"
	p.Source.Name, p.Source.UID = "approval-g2", "source-v2"
	body, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	good := Expected{OutputUID: "output-v1", SourceUID: "source-v1", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, MinimumSequence: 1, RootPins: pins}
	if _, err := VerifyCurrent(body, good, now); err != nil {
		t.Fatalf("complete pins rejected the successor: %v", err)
	}
	for name, change := range map[string]func(*Expected){
		"empty-source-uid":        func(e *Expected) { e.SourceUID = "" },
		"zero-minimum-generation": func(e *Expected) { e.MinimumGeneration = 0 },
		"source-uid-is-output":    func(e *Expected) { e.SourceUID = e.OutputUID },
		"empty-namespace":         func(e *Expected) { e.SourceNamespace = "" },
		"invalid-source-name":     func(e *Expected) { e.SourceName = "Not_An_Object" },
		"invalid-cluster":         func(e *Expected) { e.Cluster = "" },
	} {
		e := good
		change(&e)
		_, err := VerifyCurrent(body, e, now)
		t.Logf("%s: err=%v", name, err)
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
