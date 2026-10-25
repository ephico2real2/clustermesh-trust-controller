package spireregistrar

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/protobuf/proto"
	ktypes "k8s.io/apimachinery/pkg/types"
)

func TestUIDRequiresCanonicalNonzeroUUID(t *testing.T) {
	good := string(testUID("uid-validation"))
	for _, bad := range []string{"", uuid.Nil.String(), strings.ToUpper(good), "urn:uuid:" + good, "{" + good + "}", strings.ReplaceAll(good, "-", "")} {
		if uid(ktypes.UID(bad)) {
			t.Fatalf("noncanonical or nil UID accepted: %q", bad)
		}
	}
	if !uid(ktypes.UID(good)) {
		t.Fatal("canonical UID refused")
	}
}
func TestMalformedOwnedListRowsFailClosedWithoutPanic(t *testing.T) {
	o, c, _ := fixture(t)
	snapshot, err := (Source{Reader: c, Options: o}).Collect(context.Background(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"parent", "identity", "parent-domain", "spiffe-domain", "selectors", "nil-selector", "id"} {
		t.Run(mode, func(t *testing.T) {
			row := proto.Clone(snapshot.Entries[0]).(*types.Entry)
			switch mode {
			case "parent":
				row.ParentId = nil
			case "identity":
				row.SpiffeId = nil
			case "parent-domain":
				row.ParentId.TrustDomain = "wrong.example"
			case "spiffe-domain":
				row.SpiffeId.TrustDomain = "wrong.example"
			case "selectors":
				row.Selectors = nil
			case "nil-selector":
				row.Selectors[0] = nil
			case "id":
				row.Id = "not-a-uuid"
			}
			m := newEntries()
			m.rows[row.Id] = row
			r := Registrar{Source: Source{Reader: c, Options: o}, Entries: m}
			if _, err := r.Reconcile(context.Background(), time.Now()); err == nil {
				t.Fatal("malformed retained row accepted")
			}
			if len(m.operations) != 0 {
				t.Fatal("malformed retained row was modified")
			}
		})
	}
}
