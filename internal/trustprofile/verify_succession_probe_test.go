package trustprofile

import "testing"

// Succession inputs: what VerifyCurrent accepts and rejects at and above the floor generation.
func TestVerifyCurrentSuccessionInputs(t *testing.T) {
	a, pins, now := approvalFixture(t)
	g1, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	a.Generation = 2
	g2, err := Validate(encodeApproval(t, a), pins, "cmtc-a", now)
	if err != nil {
		t.Fatal(err)
	}
	expected := Expected{OutputUID: "output-v1", SourceUID: "source-v1", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, MinimumSequence: 1, RootPins: pins}
	encode := func(v *Validated, seq uint64, name, uid string) []byte {
		t.Helper()
		p := publicationFor(v, now)
		p.Sequence = seq
		p.ExpectedSourceUID, p.AcceptedSourceUID = uid, uid
		p.Source.Name, p.Source.UID = name, uid
		body, err := Encode(p)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for name, tc := range map[string]struct {
		body   []byte
		accept bool
	}{
		// At the floor generation, the pinned UID under ANOTHER NAME.
		"floor-pinned-uid-other-name": {encode(g1, 1, "approval-renamed", "source-v1"), false},
		// Above the floor, the pinned UID under another name.
		"successor-pinned-uid-other-name": {encode(g2, 2, "approval-renamed", "source-v1"), true},
		// Above the floor, the pinned name reused by a NEW UID (slot reuse).
		"successor-same-name-new-uid": {encode(g2, 2, "approval", "source-v2"), true},
		// Two different objects at the same generation above the floor: both accepted (stateless).
		"successor-gen2-object-x": {encode(g2, 2, "approval-x", "source-x"), true},
		"successor-gen2-object-y": {encode(g2, 2, "approval-y", "source-y"), true},
	} {
		_, err := VerifyCurrent(tc.body, expected, now)
		t.Logf("%s: err=%v", name, err)
		if (err == nil) != tc.accept {
			t.Errorf("%s: accepted=%v want %v (%v)", name, err == nil, tc.accept, err)
		}
	}
}
