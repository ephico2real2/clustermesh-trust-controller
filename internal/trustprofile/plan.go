package trustprofile

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// MaxHorizon is the longest approval the arbiter writes. Validate refuses more than 30 days
// (profile.go: "approval exceeds 30-day horizon"); the day between leaves room for clock skew between the arbiter
// and the verifiers.
const MaxHorizon = 29 * 24 * time.Hour

// Plan reasons: why the arbiter writes a new approval generation.
const (
	ReasonBootstrap     = "Bootstrap"
	ReasonAdopt         = "Adopt"
	ReasonIssuerAdded   = "IssuerAdded"
	ReasonIssuerRetired = "IssuerRetired"
	ReasonIssuerExpired = "IssuerExpired"
	ReasonClusterChange = "ClusterChanged"
	ReasonRenewal       = "Renewal"
)

// Hold reasons: why a cluster's change waits. A hold keeps the last approval; it never widens or extends trust.
const (
	HoldEvidenceUnavailable = "EvidenceUnavailable"
	HoldEvidenceRefused     = "EvidenceRefused"
	HoldOverlapFull         = "OverlapFull"
	HoldRetirementWaiting   = "RetirementWaiting"
	HoldRootChanged         = "RootChanged"
	HoldRenewalWaits        = "RenewalWaitsForEvidence"
	HoldExpiresWithinMargin = "ExpiresWithinMargin"
	HoldNoIssuer            = "NoIssuer"
)

type ClusterIdentity struct{ Name, TrustDomain string }

// Evidence is one pass's reading of a cluster's current SPIRE intermediate from public objects.
type Evidence struct {
	// Issuer is nil when the evidence is unavailable or refused.
	Issuer *Issuer
	// Refused marks evidence that contradicts an administrator-approved identity, such as a replaced Certificate.
	Refused bool
	Reason  string
	Message string
	// SPIRECAMaxDuration is the lifetime SPIRE requests for each CA under this intermediate (server.conf ca_ttl);
	// zero when unknown.
	SPIRECAMaxDuration time.Duration
}

// IssuerRecord is the arbiter's durable observation of one issuer key.
type IssuerRecord struct {
	Cluster, SPKISHA256 string
	NotBefore, NotAfter time.Time
	FirstCurrent        time.Time
	// Superseded is the first pass that read another key as the cluster's current intermediate.
	Superseded time.Time
	// SupersededBy is the key issued next after this one: the key every node must trust before this one retires.
	SupersededBy string
	// SPIRECAMaxDuration is the largest SPIRE CA lifetime seen while this key was current or superseded: a SPIRE CA
	// under it was signed while it was current, for the lifetime SPIRE requested then.
	SPIRECAMaxDuration time.Duration
}

// RetireAfter is when no SPIRE CA signed by this key can still be valid: SPIRE requests each CA for
// SPIRECAMaxDuration, and cert-manager stopped signing with the key before the arbiter read the successor.
func (r IssuerRecord) RetireAfter(margin time.Duration) (time.Time, bool) {
	if r.Superseded.IsZero() || r.SPIRECAMaxDuration <= 0 {
		return time.Time{}, false
	}
	return r.Superseded.Add(r.SPIRECAMaxDuration + margin), true
}

type PlanInput struct {
	Now          time.Time
	LocalCluster string
	RootPins     []string
	RootPEM      string
	Clusters     []ClusterIdentity
	Evidence     map[string]Evidence
	// Previous is the approval the consumers accept now; nil before the first.
	Previous *Approval
	// Generation is the highest generation used so far; a new approval takes Generation + 1.
	Generation uint64
	Ledger     []IssuerRecord
	// Force writes a new generation with the same issuers (ReasonAdopt) when nothing else is due.
	Force                                  bool
	Horizon, RenewBefore, RetirementMargin time.Duration
	// MeshTrusts reports whether every node of every cluster trusts this issuer of this cluster. It is asked only
	// for a retirement that is otherwise due.
	MeshTrusts func(cluster, spki string) bool
}

type Hold struct{ Cluster, Reason, Message string }

type Plan struct {
	// Next is nil when the current approval stays.
	Next   *Approval
	Reason string
	Holds  []Hold
	// Current is each cluster's current issuer key from fresh evidence.
	Current map[string]string
	Ledger  []IssuerRecord
}

func (in PlanInput) validate() error {
	if !ClusterValid(in.LocalCluster) || len(in.Clusters) == 0 || len(in.Clusters) > 16 || in.Now.IsZero() || in.MeshTrusts == nil {
		return errors.New("plan needs the local cluster, the clusters, a time and the mesh trust gate")
	}
	if in.Horizon <= 0 || in.Horizon > MaxHorizon || in.RenewBefore <= 0 || in.RenewBefore >= in.Horizon || in.RetirementMargin <= 0 || in.RetirementMargin >= in.RenewBefore {
		return fmt.Errorf("need 0 < retirementMargin < renewBefore < horizon <= %s", MaxHorizon)
	}
	names, local := map[string]bool{}, false
	for _, c := range in.Clusters {
		if !ClusterValid(c.Name) || names[c.Name] || c.TrustDomain == "" {
			return errors.New("invalid or duplicate cluster identity")
		}
		names[c.Name] = true
		local = local || c.Name == in.LocalCluster
	}
	if !local {
		return errors.New("the local cluster is not a configured cluster")
	}
	return nil
}

type ledgerKey struct{ cluster, spki string }

// PlanApproval decides the next approval from the evidence, the accepted approval and the ledger. It is pure. The
// rules (ADR-012): add a cluster's current intermediate as soon as fresh evidence shows it; keep its predecessor until
// RetireAfter has passed and every node of every cluster trusts the successor; drop an issuer only when retired or
// within the margin of its own expiry; never hold more than two issuers per cluster; never extend the expiry from
// evidence that is unavailable or refused.
func PlanApproval(in PlanInput) (Plan, error) {
	if err := in.validate(); err != nil {
		return Plan{}, err
	}
	now := in.Now.UTC()
	root, err := ParseRoot(in.RootPEM, in.RootPins, now)
	if err != nil {
		return Plan{}, err
	}
	rootSHA := SHA(root.Raw)
	ledger := map[ledgerKey]*IssuerRecord{}
	for _, r := range in.Ledger {
		r := r
		ledger[ledgerKey{r.Cluster, r.SPKISHA256}] = &r
	}
	record := func(cluster string, issuer Issuer) (*IssuerRecord, error) {
		cert, err := oneCertificate(issuer.CertificatePEM)
		if err != nil {
			return nil, err
		}
		k := ledgerKey{cluster, issuer.SPKISHA256}
		if ledger[k] == nil {
			ledger[k] = &IssuerRecord{Cluster: cluster, SPKISHA256: issuer.SPKISHA256}
		}
		// The certificate, not the stored record, is the source of the validity window.
		ledger[k].NotBefore, ledger[k].NotAfter = cert.NotBefore.UTC(), cert.NotAfter.UTC()
		return ledger[k], nil
	}
	plan := Plan{Current: map[string]string{}}
	if in.Previous != nil && (len(in.Previous.Roots) != 1 || in.Previous.Roots[0].SHA256 != rootSHA) {
		// The approval schema carries one root (Validate), so a root change has no overlap: refuse it.
		plan.Holds = append(plan.Holds, Hold{Reason: HoldRootChanged, Message: "the mesh root differs from the accepted approval's root"})
		plan.Ledger = in.Ledger
		return plan, nil
	}
	previous := map[string]Cluster{}
	if in.Previous != nil {
		for _, c := range in.Previous.Clusters {
			previous[c.ClusterID] = c
		}
	}
	clusters := append([]ClusterIdentity(nil), in.Clusters...)
	sort.Slice(clusters, func(i, j int) bool { return clusters[i].Name < clusters[j].Name })
	var next []Cluster
	stale, missing := false, false
	added, retired, expired := false, false, false
	expires := now.Add(in.Horizon)
	if root.NotAfter.Before(expires) {
		expires = root.NotAfter
	}
	for _, c := range clusters {
		var prior []Issuer
		if p, ok := previous[c.Name]; ok && p.TrustDomain == c.TrustDomain {
			prior = p.Issuers
		}
		ev, ok := in.Evidence[c.Name]
		if !ok {
			ev = Evidence{Reason: HoldEvidenceUnavailable, Message: "no evidence read"}
		}
		var current *Issuer
		if ev.Issuer != nil && !ev.Refused {
			current = ev.Issuer
		} else {
			reason := HoldEvidenceUnavailable
			if ev.Refused {
				reason = HoldEvidenceRefused
			}
			plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: reason, Message: strings.TrimSpace(ev.Reason + " " + ev.Message)})
			stale = true
		}
		var records []*IssuerRecord
		for _, p := range prior {
			r, err := record(c.Name, p)
			if err != nil {
				return Plan{}, fmt.Errorf("accepted issuer of %s: %w", c.Name, err)
			}
			records = append(records, r)
		}
		if current != nil {
			r, err := record(c.Name, *current)
			if err != nil {
				return Plan{}, err
			}
			records = append(records, r)
		}
		var keep []Issuer
		for i, p := range prior {
			r := records[i]
			if current != nil && p.SPKISHA256 == current.SPKISHA256 {
				continue
			}
			if !now.Add(in.RetirementMargin).Before(r.NotAfter) {
				expired = true
				continue
			}
			if current == nil {
				keep = append(keep, p)
				continue
			}
			if r.Superseded.IsZero() {
				r.Superseded = now
			}
			r.SupersededBy = successor(r, records, current.SPKISHA256)
			if ev.SPIRECAMaxDuration > r.SPIRECAMaxDuration {
				r.SPIRECAMaxDuration = ev.SPIRECAMaxDuration
			}
			retireAfter, known := r.RetireAfter(in.RetirementMargin)
			switch {
			// An unknown reading holds even after a known one: SPIRE may run with a ca_ttl the arbiter cannot read.
			case !known || ev.SPIRECAMaxDuration <= 0:
				plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: HoldRetirementWaiting, Message: "the SPIRE CA lifetime bound is unknown; " + p.SPKISHA256 + " stays"})
			case now.Before(retireAfter):
				plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: HoldRetirementWaiting, Message: p.SPKISHA256 + " stays until " + Stamp(retireAfter)})
			case !in.MeshTrusts(c.Name, r.SupersededBy):
				plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: HoldRetirementWaiting, Message: p.SPKISHA256 + " stays until every node of every cluster trusts " + r.SupersededBy})
			default:
				retired = true
				continue
			}
			keep = append(keep, p)
		}
		issuers := keep
		if current != nil {
			r := records[len(records)-1]
			r.Superseded, r.SupersededBy = time.Time{}, ""
			if r.FirstCurrent.IsZero() {
				r.FirstCurrent = now
			}
			if ev.SPIRECAMaxDuration > r.SPIRECAMaxDuration {
				r.SPIRECAMaxDuration = ev.SPIRECAMaxDuration
			}
			plan.Current[c.Name] = current.SPKISHA256
			inPrior := false
			for _, p := range prior {
				inPrior = inPrior || p.SPKISHA256 == current.SPKISHA256
			}
			switch {
			case len(keep) >= 2:
				// A third key while two are still live: neither may go, so the new one waits.
				plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: HoldOverlapFull, Message: current.SPKISHA256 + " waits: two earlier issuers are still live"})
				stale = true
			default:
				issuers = append(issuers, *current)
				added = added || !inPrior
			}
		}
		if len(issuers) == 0 {
			plan.Holds = append(plan.Holds, Hold{Cluster: c.Name, Reason: HoldNoIssuer, Message: "no live issuer to approve"})
			missing = true
			continue
		}
		sort.Slice(issuers, func(i, j int) bool { return issuers[i].SPKISHA256 < issuers[j].SPKISHA256 })
		for _, i := range issuers {
			notAfter, err := IssuerNotAfter(i)
			if err != nil {
				return Plan{}, err
			}
			if notAfter.Before(expires) {
				expires = notAfter
			}
		}
		next = append(next, Cluster{ClusterID: c.Name, TrustDomain: c.TrustDomain, Issuers: issuers})
	}
	var previousExpiry time.Time
	if in.Previous != nil {
		if previousExpiry, err = parseTime(in.Previous.ExpiresAt); err != nil {
			return Plan{}, err
		}
		if stale && previousExpiry.Before(expires) {
			expires = previousExpiry
		}
	}
	expires = expires.UTC().Truncate(time.Second)
	candidate := &Approval{SchemaVersion: SchemaVersion, Generation: in.Generation + 1, ExpiresAt: Stamp(expires),
		Roots: []Root{{CertificatePEM: canonical(root), SHA256: rootSHA}}, Clusters: next}
	switch {
	case in.Previous == nil:
		if !missing && !stale {
			plan.Next, plan.Reason = candidate, ReasonBootstrap
		}
	case !sameIssuers(in.Previous, candidate):
		plan.Next = candidate
		switch {
		case added:
			plan.Reason = ReasonIssuerAdded
		case retired:
			plan.Reason = ReasonIssuerRetired
		case expired:
			plan.Reason = ReasonIssuerExpired
		default:
			plan.Reason = ReasonClusterChange
		}
	case in.Force:
		plan.Next, plan.Reason = candidate, ReasonAdopt
	case !now.Add(in.RenewBefore).Before(previousExpiry):
		if expires.After(previousExpiry) {
			plan.Next, plan.Reason = candidate, ReasonRenewal
		} else {
			plan.Holds = append(plan.Holds, Hold{Reason: HoldRenewalWaits, Message: "renewal is due and no fresh evidence extends the expiry " + in.Previous.ExpiresAt})
		}
	}
	local := false
	for _, c := range next {
		local = local || c.ClusterID == in.LocalCluster
	}
	if plan.Next != nil && (!local || !expires.After(now.Add(in.RetirementMargin))) {
		plan.Holds = append(plan.Holds, Hold{Cluster: in.LocalCluster, Reason: HoldExpiresWithinMargin, Message: "the next approval would lack the local cluster or end within the retirement margin"})
		plan.Next, plan.Reason = nil, ""
	}
	plan.Ledger = keptRecords(ledger, in.Previous, plan.Next, plan.Current)
	return plan, nil
}

// successor is the key cert-manager issued next after r's: the earliest later notBefore among the cluster's keys, or
// the current key. A third key that waits outside the approval is then the successor of the second key only, so the
// first key can still retire on the mesh's trust in the second, and the third enters in the same generation.
func successor(r *IssuerRecord, records []*IssuerRecord, current string) string {
	next := ""
	var at time.Time
	for _, o := range records {
		if o.SPKISHA256 == r.SPKISHA256 || !o.NotBefore.After(r.NotBefore) {
			continue
		}
		if next == "" || o.NotBefore.Before(at) {
			next, at = o.SPKISHA256, o.NotBefore
		}
	}
	if next == "" {
		return current
	}
	return next
}

// keptRecords keeps the record of every issuer still approved, about to be approved or current.
func keptRecords(ledger map[ledgerKey]*IssuerRecord, approvals ...any) []IssuerRecord {
	live := map[ledgerKey]bool{}
	for _, a := range approvals {
		switch v := a.(type) {
		case *Approval:
			if v == nil {
				continue
			}
			for _, c := range v.Clusters {
				for _, i := range c.Issuers {
					live[ledgerKey{c.ClusterID, i.SPKISHA256}] = true
				}
			}
		case map[string]string:
			for cluster, spki := range v {
				live[ledgerKey{cluster, spki}] = true
			}
		}
	}
	var out []IssuerRecord
	for k, r := range ledger {
		if live[k] {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cluster != out[j].Cluster {
			return out[i].Cluster < out[j].Cluster
		}
		return out[i].SPKISHA256 < out[j].SPKISHA256
	})
	return out
}

func issuerSet(a *Approval) map[string]string {
	set := map[string]string{}
	for _, c := range a.Clusters {
		var keys []string
		for _, i := range c.Issuers {
			keys = append(keys, i.SPKISHA256)
		}
		sort.Strings(keys)
		set[c.ClusterID] = c.TrustDomain + "|" + strings.Join(keys, ",")
	}
	return set
}

func sameIssuers(a, b *Approval) bool {
	x, y := issuerSet(a), issuerSet(b)
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}

// CheckSuccession is the overlap invariant, checked again on the candidate before it is written: every issuer of the
// accepted approval is still in the next one unless it expires within the margin, or its ledger record allows its
// retirement now and every node of every cluster trusts an issuer that the next approval keeps for that cluster.
func CheckSuccession(previous, next *Approval, ledger []IssuerRecord, now time.Time, margin time.Duration, meshTrusts func(cluster, spki string) bool) error {
	if previous == nil {
		return nil
	}
	records := map[ledgerKey]IssuerRecord{}
	for _, r := range ledger {
		records[ledgerKey{r.Cluster, r.SPKISHA256}] = r
	}
	kept := map[ledgerKey]bool{}
	nextByCluster := map[string][]Issuer{}
	for _, c := range next.Clusters {
		nextByCluster[c.ClusterID] = c.Issuers
		for _, i := range c.Issuers {
			kept[ledgerKey{c.ClusterID, i.SPKISHA256}] = true
		}
	}
	for _, c := range previous.Clusters {
		if _, ok := nextByCluster[c.ClusterID]; !ok {
			// A cluster that leaves the approval is a configuration change or has no live issuer; it is not a
			// succession inside the cluster.
			continue
		}
		for _, p := range c.Issuers {
			k := ledgerKey{c.ClusterID, p.SPKISHA256}
			if kept[k] {
				continue
			}
			notAfter, err := IssuerNotAfter(p)
			if err != nil {
				return err
			}
			if !now.Add(margin).Before(notAfter) {
				continue
			}
			r, ok := records[k]
			retireAfter, known := r.RetireAfter(margin)
			successor := r.SupersededBy != "" && kept[ledgerKey{c.ClusterID, r.SupersededBy}] && meshTrusts(c.ClusterID, r.SupersededBy)
			if !ok || !known || now.Before(retireAfter) || !successor {
				return fmt.Errorf("NoOverlap: %s issuer %s would be dropped while SPIRE CAs under it may be live", c.ClusterID, p.SPKISHA256)
			}
		}
	}
	return nil
}
