package spireregistrar

import (
	"context"
	"errors"
	"fmt"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sort"
	"strings"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Registrar struct {
	Source  Source
	Entries entryv1.EntryClient
}

func (r Registrar) list(ctx context.Context) ([]*types.Entry, error) {
	entries := []*types.Entry{}
	seen := map[string]bool{}
	pages := map[string]bool{}
	token := ""
	for {
		if pages[token] {
			return nil, errors.New("SPIRE repeated a registration page token")
		}
		pages[token] = true
		response, err := r.Entries.ListEntries(ctx, &entryv1.ListEntriesRequest{Filter: &entryv1.ListEntriesRequest_Filter{ByHint: wrapperspb.String(r.Source.Options.Hint())}, PageSize: 128, PageToken: token})
		if err != nil {
			return nil, err
		}
		if response == nil {
			return nil, errors.New("SPIRE registration list is nil")
		}
		for _, entry := range response.Entries {
			if entry == nil || entry.Hint != r.Source.Options.Hint() || !uid(ktypes.UID(entry.Id)) || seen[entry.Id] || !ownedShape(entry, r.Source.Options) {
				return nil, errors.New("SPIRE returned malformed/colliding ownership rows")
			}
			// Never adopt a row that can delegate administration or federation.
			if entry.Admin || entry.Downstream || entry.StoreSvid || len(entry.FederatesWith) != 0 || len(entry.DnsNames) != 0 || entry.ExpiresAt == 0 {
				return nil, errors.New("owned registrar row contains forbidden authority or unbounded lifetime")
			}
			seen[entry.Id] = true
			entries = append(entries, entry)
		}
		if len(entries) > 128 || len(pages) > 16 {
			return nil, errors.New("SPIRE registration inventory bound exceeded")
		}
		token = response.NextPageToken
		if token == "" {
			return entries, nil
		}
	}
}

// ownedShape accepts only the two explicit formats this registrar can create.
// Hint is an ownership marker inside the trusted server-admin boundary, not
// an authorization claim against a malicious or concurrent SPIRE administrator.
func ownedShape(e *types.Entry, o Options) bool {
	if e == nil || e.ParentId == nil || e.SpiffeId == nil || e.ParentId.TrustDomain != o.TrustDomain || e.SpiffeId.TrustDomain != o.TrustDomain {
		return false
	}
	alias := func(path string) bool {
		parts := strings.Split(path, "/")
		return len(parts) == 5 && parts[0] == "" && parts[1] == "cmtc" && parts[2] == "agents" && uid(ktypes.UID(parts[3])) && uid(ktypes.UID(parts[4]))
	}
	kind := "k8s"
	if e.ParentId.Path == "/spire/server" {
		if !alias(e.SpiffeId.Path) || len(e.Selectors) != 6 {
			return false
		}
		kind = "k8s_psat"
	} else {
		if !alias(e.ParentId.Path) || len(e.Selectors) != 4 {
			return false
		}
		if e.SpiffeId.Path != "/ztunnel-proxy" {
			parts := strings.Split(e.SpiffeId.Path, "/")
			if len(parts) != 5 || parts[0] != "" || parts[1] != "ns" || parts[3] != "sa" || !dns(parts[2]) || !dns(parts[4]) {
				return false
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range e.Selectors {
		if s == nil || s.Type != kind || s.Value == "" || seen[s.Value] {
			return false
		}
		seen[s.Value] = true
	}
	return true
}

// sameMaterial rejects any selector/identity/authority change, including unknown
// future fields. Only server-generated bookkeeping and the renewable expiry are
// excluded. Changing the immutable binding creates a different deterministic ID.
func sameMaterial(a, b *types.Entry) bool {
	if a == nil || b == nil {
		return false
	}
	aa := proto.Clone(a).(*types.Entry)
	bb := proto.Clone(b).(*types.Entry)
	aa.CreatedAt = 0
	aa.RevisionNumber = 0
	aa.ExpiresAt = 0
	bb.CreatedAt = 0
	bb.RevisionNumber = 0
	bb.ExpiresAt = 0
	// Selector ordering has no authority semantics, but duplicate selectors do.
	order := func(e *types.Entry) bool {
		for _, s := range e.Selectors {
			if s == nil {
				return false
			}
		}
		sort.Slice(e.Selectors, func(i, j int) bool {
			a, b := e.Selectors[i], e.Selectors[j]
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			return a.Value < b.Value
		})
		for i := 1; i < len(e.Selectors); i++ {
			if proto.Equal(e.Selectors[i-1], e.Selectors[i]) {
				return false
			}
		}
		return true
	}
	return order(aa) && order(bb) && proto.Equal(aa, bb)
}

func (r Registrar) remove(ctx context.Context, entry *types.Entry) error {
	// A name/ID alone is not an ownership check. Re-read the exact owned row.
	actual, err := r.Entries.GetEntry(ctx, &entryv1.GetEntryRequest{Id: entry.Id})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}
	if actual == nil || actual.Hint != r.Source.Options.Hint() || !sameMaterial(actual, entry) {
		return errors.New("registration changed before deletion; refusing foreign cleanup")
	}
	response, err := r.Entries.BatchDeleteEntry(ctx, &entryv1.BatchDeleteEntryRequest{Ids: []string{entry.Id}})
	if err != nil {
		return err
	}
	if response == nil || len(response.Results) != 1 || response.Results[0] == nil || response.Results[0].Status == nil || response.Results[0].Id != entry.Id {
		return errors.New("malformed SPIRE deletion acknowledgment")
	}
	code := codes.Code(response.Results[0].Status.Code)
	if code != codes.OK && code != codes.NotFound {
		return status.Error(code, response.Results[0].Status.Message)
	}
	_, err = r.Entries.GetEntry(ctx, &entryv1.GetEntryRequest{Id: entry.Id})
	if status.Code(err) != codes.NotFound {
		if err == nil {
			return errors.New("SPIRE deletion was acknowledged but row is still present")
		}
		return err
	}
	return nil
}

func (r Registrar) upsert(ctx context.Context, want *types.Entry) error {
	current, err := r.Entries.GetEntry(ctx, &entryv1.GetEntryRequest{Id: want.Id})
	if status.Code(err) == codes.NotFound {
		response, createErr := r.Entries.BatchCreateEntry(ctx, &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{want}})
		if createErr != nil {
			return createErr
		}
		if response == nil || len(response.Results) != 1 || response.Results[0] == nil || response.Results[0].Status == nil {
			return errors.New("malformed SPIRE creation acknowledgment")
		}
		result := response.Results[0]
		code := codes.Code(result.Status.Code)
		if code != codes.OK && code != codes.AlreadyExists {
			return status.Error(code, result.Status.Message)
		}
		if result.Entry == nil || result.Entry.Id != want.Id || !sameMaterial(result.Entry, want) {
			return errors.New("SPIRE create collision or mismatched returned row")
		}
		current = result.Entry
	} else if err != nil {
		return err
	}
	if !sameMaterial(current, want) {
		return errors.New("SPIRE immutable registration binding collision")
	}
	// Renew only expiry. Never turn a conflicting entry into an entitled workload.
	if current.ExpiresAt != want.ExpiresAt {
		response, err := r.Entries.BatchUpdateEntry(ctx, &entryv1.BatchUpdateEntryRequest{Entries: []*types.Entry{want}, InputMask: &types.EntryMask{ExpiresAt: true}})
		if err != nil {
			return err
		}
		if response == nil || len(response.Results) != 1 || response.Results[0] == nil || response.Results[0].Status == nil || response.Results[0].Status.Code != int32(codes.OK) {
			return errors.New("SPIRE expiry renewal was not explicitly acknowledged")
		}
	}
	actual, err := r.Entries.GetEntry(ctx, &entryv1.GetEntryRequest{Id: want.Id})
	if err != nil {
		return err
	}
	if !sameMaterial(actual, want) || actual.ExpiresAt != want.ExpiresAt {
		return errors.New("SPIRE registration readback does not match exact desired binding/expiry")
	}
	return nil
}

func (r Registrar) Withdraw(ctx context.Context) error {
	entries, err := r.list(ctx)
	if err != nil {
		return err
	}
	// Children first. No broad parent or namespace deletes.
	entryOrder(entries)
	for i := len(entries) - 1; i >= 0; i-- {
		if err := r.remove(ctx, entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// Reconcile performs one bounded current-API pass. A successful SPIRE readback
// acknowledges registration only. It does not assert SVID minting or protection.
func (r Registrar) Reconcile(ctx context.Context, now time.Time) (int, error) {
	existing, err := r.list(ctx)
	if err != nil {
		return 0, err
	}
	snapshot, err := r.Source.Collect(ctx, now)
	if err != nil {
		return 0, err
	}
	wanted := map[string]*types.Entry{}
	for _, entry := range snapshot.Entries {
		wanted[entry.Id] = entry
	}
	entryOrder(existing)
	for i := len(existing) - 1; i >= 0; i-- {
		old := existing[i]
		if wanted[old.Id] == nil {
			if err := r.remove(ctx, old); err != nil {
				return 0, err
			}
		}
	}
	for _, want := range snapshot.Entries {
		if err := snapshot.Recheck(ctx, r.Source.Reader); err != nil {
			return 0, err
		}
		if err := r.upsert(ctx, want); err != nil {
			return 0, fmt.Errorf("SPIRE exact registration %s: %w", want.Id, err)
		}
	}
	if err := snapshot.Recheck(ctx, r.Source.Reader); err != nil {
		return 0, err
	}
	return len(snapshot.Entries), nil
}
