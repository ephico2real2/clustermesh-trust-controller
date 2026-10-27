package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Arbiter timing. The producer renews the publication lease on its own 5 s loop, so a slow or failed arbiter pass
// never shortens the lease.
const (
	issuerApprovalPoll        = 15 * time.Second
	issuerApprovalPassTimeout = 12 * time.Second
	// pendingPublishWarning is how long a written slot may wait for the producer before the arbiter reports it.
	pendingPublishWarning = 2 * time.Minute
	// DefaultReportMaxAge is four node-agent heartbeats (agent.ReportHeartbeat).
	DefaultReportMaxAge = 2 * time.Minute
)

// Labels and annotations of an approval slot. Slots carry no ownerReferences: the Cilium agent refuses an approval
// source that has any (pkg/ztunnel/issuerprofile/project.go:208 in the Cilium fork), so the arbiter deletes them.
const (
	SlotLabel            = "security.cmtc.io/issuer-approval-slot"
	SlotGenerationLabel  = "security.cmtc.io/issuer-approval-generation"
	SlotReasonAnnotation = "security.cmtc.io/issuer-approval-reason"
)

// Condition types of the IssuerApproval status.
const (
	ConditionEvidenceReady  = "EvidenceReady"
	ConditionNodesConverged = "NodesConverged"
	ConditionBlocked        = "Blocked"
)

// Block reasons of the arbiter itself; the planner's holds add their own (trustprofile.Hold*).
const (
	BlockForeignSlot         = "ForeignSlot"
	BlockPlanFailed          = "PlanFailed"
	BlockMeshNotConverged    = "MeshNotConverged"
	BlockNoFreeSlot          = "NoFreeSlot"
	BlockWriteRefused        = "WriteRefused"
	BlockPendingNotPublished = "PendingNotPublished"
)

// ApprovalCluster is one cluster the administrator approved: its name, trust domain, and the cert-manager
// Certificate (by name and UID) whose issued intermediate signs its SPIRE CA.
type ApprovalCluster struct {
	Name           string    `json:"name"`
	TrustDomain    string    `json:"trustDomain"`
	Certificate    string    `json:"certificate"`
	CertificateUID types.UID `json:"certificateUID"`
	// SPIRECAPolicy is the approver-policy CertificateRequestPolicy that bounds the cluster's SPIRE CA lifetime.
	SPIRECAPolicy string `json:"spireCAPolicy"`
}

// IssuerApprovalOptions configure the arbiter. Every cluster of the mesh runs the same chart, so the namespaces and
// object names are the same on every cluster.
type IssuerApprovalOptions struct {
	// Namespace holds the slots, the publication, the IssuerApproval and trust-manager's mesh root ConfigMap.
	Namespace string
	Slots     [2]string
	// AdoptSource is the approval the producer published before the arbiter existed; the producer follows it until
	// the arbiter's first generation is published. The arbiter never writes or deletes it.
	AdoptSource string
	Output      string
	// RootConfigMap is trust-manager's copy of the mesh root (key ca.crt) in Namespace.
	RootConfigMap        string
	CertManagerNamespace string
	RootIssuer           string
	SPIRENamespace       string
	SPIREConfigMap       string
	LocalCluster         string
	RootPins             []string
	MinimumGeneration    uint64
	Clusters             []ApprovalCluster
	Horizon              time.Duration
	RenewBefore          time.Duration
	RetirementMargin     time.Duration
	ReportMaxAge         time.Duration
}

func (o IssuerApprovalOptions) Validate() error {
	if o.Namespace == "" || o.Slots[0] == "" || o.Slots[1] == "" || o.Output == "" || o.RootConfigMap == "" || o.CertManagerNamespace == "" || o.RootIssuer == "" || o.SPIRENamespace == "" || o.SPIREConfigMap == "" || o.MinimumGeneration == 0 || o.ReportMaxAge <= 0 || len(o.RootPins) == 0 || len(o.RootPins) > 4 {
		return errors.New("issuer approval arbiter needs its namespace, two slots, the output, the mesh root, the SPIRE server config, a minimum generation, root pins and a report age")
	}
	names := map[string]bool{}
	for _, n := range []string{o.Slots[0], o.Slots[1], o.Output, o.RootConfigMap, o.AdoptSource} {
		if n != "" && names[n] {
			return errors.New("slot, output, root and adopted ConfigMap names must differ")
		}
		names[n] = true
	}
	for _, pin := range o.RootPins {
		if !trustprofile.PinValid(pin) {
			return errors.New("invalid root pin")
		}
	}
	if o.Horizon <= 0 || o.Horizon > trustprofile.MaxHorizon || o.RenewBefore <= 0 || o.RenewBefore >= o.Horizon || o.RetirementMargin <= 0 || o.RetirementMargin >= o.RenewBefore {
		return fmt.Errorf("need 0 < retirementMargin < renewBefore < horizon <= %s", trustprofile.MaxHorizon)
	}
	seen, local := map[string]bool{}, false
	for _, c := range o.Clusters {
		if !trustprofile.ClusterValid(c.Name) || seen[c.Name] || c.TrustDomain == "" || c.Certificate == "" || c.CertificateUID == "" || c.SPIRECAPolicy == "" {
			return fmt.Errorf("cluster %q must be unique and needs a trust domain, its intermediate Certificate name and UID and its SPIRE CA policy", c.Name)
		}
		seen[c.Name] = true
		local = local || c.Name == o.LocalCluster
	}
	if !local {
		return errors.New("the local cluster must be one of the approved clusters")
	}
	return nil
}

// IssuerApprovalReconciler is the issuer approval arbiter (ADR-012): the single leader-elected writer of the approval
// slots. Each pass re-derives its state from the publication, the slots and the IssuerApproval record, so a restart
// resumes where the last pass stopped. A pass changes at most one slot, and only on observed evidence: cert-manager's
// public objects, the producer's publication, and the node reports of every cluster.
type IssuerApprovalReconciler struct {
	// Client writes the slots and the IssuerApproval.
	Client client.Client
	// Reader reads the slots, the publication and the local evidence directly from the API server.
	Reader client.Reader
	// Cache reads the local Node metadata and NodeTrustReports from the manager's informers.
	Cache client.Reader
	// Peers read each remote cluster's public evidence, publication and node reports, by cluster name.
	Peers   map[string]client.Reader
	Options IssuerApprovalOptions
	Metrics *trustprofile.ArbiterMetrics
	Now     func() time.Time

	attempt    atomic.Uint64
	mu         sync.Mutex
	heartbeats map[string]heartbeat
}

func (r *IssuerApprovalReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func (r *IssuerApprovalReconciler) key(name string) client.ObjectKey {
	return client.ObjectKey{Namespace: r.Options.Namespace, Name: name}
}

func (r *IssuerApprovalReconciler) isSlot(name string) bool {
	return name == r.Options.Slots[0] || name == r.Options.Slots[1]
}

// reader is the API reader of a cluster's public evidence; nil for a peer without credentials.
func (r *IssuerApprovalReconciler) reader(cluster string) client.Reader {
	if cluster == r.Options.LocalCluster {
		return r.Reader
	}
	if peer := r.Peers[cluster]; peer != nil {
		return peer
	}
	return nil
}

// slot is one slot ConfigMap as a pass read it. invalid names why an existing object cannot be used.
type slot struct {
	name     string
	object   *corev1.ConfigMap
	approval *trustprofile.Approval
	invalid  string
}

const notArbiterSlot = "not an arbiter slot"

func (s slot) generation() uint64 {
	if s.approval == nil {
		return 0
	}
	return s.approval.Generation
}

func (r *IssuerApprovalReconciler) readSlot(ctx context.Context, name string) (slot, error) {
	s := slot{name: name}
	var cm corev1.ConfigMap
	err := r.Reader.Get(ctx, r.key(name), &cm)
	if apierrors.IsNotFound(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	s.object = &cm
	switch {
	case cm.Labels[SlotLabel] != "true" || len(cm.OwnerReferences) > 0:
		s.invalid = notArbiterSlot
	case cm.DeletionTimestamp != nil:
		s.invalid = "being deleted"
	case cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) > 0:
		s.invalid = "not one immutable approval"
	default:
		a, err := trustprofile.DecodeApproval([]byte(cm.Data[trustprofile.ApprovalKey]))
		if err != nil {
			s.invalid = err.Error()
		} else {
			s.approval = a
		}
	}
	return s, nil
}

// readPublication reads a cluster's producer output; nil when the producer has not written it yet.
func (r *IssuerApprovalReconciler) readPublication(ctx context.Context, reader client.Reader) (*trustprofile.Publication, error) {
	var out corev1.ConfigMap
	if err := reader.Get(ctx, r.key(r.Options.Output), &out); err != nil {
		return nil, err
	}
	raw := out.Data[trustprofile.DataKey]
	if raw == "" {
		return nil, nil
	}
	return trustprofile.DecodePublication([]byte(raw))
}

func (r *IssuerApprovalReconciler) record(ctx context.Context) (*api.IssuerApproval, error) {
	var record api.IssuerApproval
	err := r.Reader.Get(ctx, r.key(api.IssuerApprovalName), &record)
	if apierrors.IsNotFound(err) {
		record = api.IssuerApproval{ObjectMeta: metav1.ObjectMeta{Namespace: r.Options.Namespace, Name: api.IssuerApprovalName}}
		if err = r.Client.Create(ctx, &record); err != nil {
			return nil, fmt.Errorf("create the IssuerApproval record: %w", err)
		}
		return &record, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the IssuerApproval record: %w", err)
	}
	return &record, nil
}

// FollowedSource names the approval the producer publishes: the pending slot once it validates, otherwise the
// current slot, otherwise the publication's accepted source when that is a slot or the adopted source. The producer
// validates whatever this returns with its own rules and generation floors. An error stops the producer's pass
// without a write, so the last lease runs out instead of being renewed.
func (r *IssuerApprovalReconciler) FollowedSource(ctx context.Context, previous *trustprofile.Publication) (client.ObjectKey, types.UID, error) {
	var record api.IssuerApproval
	if err := r.Reader.Get(ctx, r.key(api.IssuerApprovalName), &record); err != nil && !apierrors.IsNotFound(err) {
		return client.ObjectKey{}, "", fmt.Errorf("read the IssuerApproval record: %w", err)
	}
	if p := record.Status.Pending; p != nil && r.isSlot(p.Slot) {
		s, err := r.readSlot(ctx, p.Slot)
		if err != nil {
			return client.ObjectKey{}, "", err
		}
		if s.object != nil && string(s.object.UID) == p.UID && s.invalid == "" {
			if _, err := trustprofile.Validate([]byte(s.object.Data[trustprofile.ApprovalKey]), r.Options.RootPins, r.Options.LocalCluster, r.now()); err == nil {
				return r.key(p.Slot), types.UID(p.UID), nil
			}
		}
	}
	if c := record.Status.Current; c != nil && r.isSlot(c.Slot) && c.UID != "" {
		return r.key(c.Slot), types.UID(c.UID), nil
	}
	if previous != nil && previous.AcceptedSourceUID != "" && previous.Source.Namespace == r.Options.Namespace && previous.Source.UID == previous.AcceptedSourceUID &&
		(r.isSlot(previous.Source.Name) || r.Options.AdoptSource != "" && previous.Source.Name == r.Options.AdoptSource) {
		return r.key(previous.Source.Name), types.UID(previous.AcceptedSourceUID), nil
	}
	return client.ObjectKey{}, "", errors.New("the issuer approval arbiter names no approval yet")
}

// target is what every node of a cluster must accept: the generation of that cluster's live publication.
type target struct {
	live       bool
	generation uint64
	digest     string
	root       string
}

func publicationTarget(p *trustprofile.Publication, now time.Time) target {
	if p == nil || p.State != "published" || p.Approval == nil || len(p.Approval.Roots) != 1 {
		return target{}
	}
	until, err := time.Parse(time.RFC3339, p.ValidUntil)
	if err != nil || !now.Before(until) {
		return target{}
	}
	return target{live: true, generation: p.AcceptedGeneration, digest: p.AcceptedApprovalDigest, root: p.Approval.Roots[0].SHA256}
}

// passState is what one pass read of the local approval objects.
type passState struct {
	publication *trustprofile.Publication
	slots       map[string]slot
	// current is the slot the publication names as its accepted source.
	current *slot
	pending *slot
	// accepted is the approval the consumers accept now, or last accepted: the current slot's, else the published one.
	accepted *trustprofile.Approval
	// generation is the highest generation used so far.
	generation uint64
	published  bool
}

func (r *IssuerApprovalReconciler) readState(ctx context.Context, record *api.IssuerApproval) (passState, error) {
	st := passState{slots: map[string]slot{}, generation: r.Options.MinimumGeneration - 1}
	var err error
	if st.publication, err = r.readPublication(ctx, r.Reader); err != nil {
		return st, fmt.Errorf("read the publication: %w", err)
	}
	for _, name := range r.Options.Slots {
		s, err := r.readSlot(ctx, name)
		if err != nil {
			return st, fmt.Errorf("read slot %s: %w", name, err)
		}
		st.slots[name] = s
		st.generation = max(st.generation, s.generation())
	}
	acceptedGeneration := uint64(0)
	if p := st.publication; p != nil {
		acceptedGeneration = p.AcceptedGeneration
		st.generation = max(st.generation, p.AcceptedGeneration)
		st.published = p.State == "published"
		for _, name := range r.Options.Slots {
			s := st.slots[name]
			if s.object != nil && s.invalid == "" && p.AcceptedSourceUID != "" && string(s.object.UID) == p.AcceptedSourceUID && s.generation() == p.AcceptedGeneration {
				st.current, st.accepted = &s, s.approval
			}
		}
		if st.accepted == nil && st.published {
			st.accepted = p.Approval
		}
	}
	if pend := record.Status.Pending; pend != nil && r.isSlot(pend.Slot) {
		s := st.slots[pend.Slot]
		if s.object != nil && string(s.object.UID) == pend.UID && s.invalid == "" && s.generation() > acceptedGeneration {
			st.pending = &s
		}
	}
	return st, nil
}

func ref(s *slot, reason string) *api.ApprovalRef {
	if s == nil || s.object == nil || s.approval == nil {
		return nil
	}
	expires, _ := time.Parse(time.RFC3339, s.approval.ExpiresAt)
	// A slot holds the producer's canonical approval bytes, so this is the digest the producer publishes.
	digest := trustprofile.SHA([]byte(s.object.Data[trustprofile.ApprovalKey]))
	return &api.ApprovalRef{Slot: s.name, UID: string(s.object.UID), Generation: s.generation(), Digest: digest, ExpiresAt: metav1.NewTime(expires), Reason: reason}
}

// clusterView is one cluster's nodes and reports as one pass read them, and the generation they must accept.
type clusterView struct {
	views   []nodeView
	target  target
	err     error
	summary api.NodeSummary
}

// converged: every node reports fresh and, while the cluster's publication is live, accepts its generation. A
// cluster without nodes is not converged.
func (v *clusterView) converged() bool {
	return v.err == nil && len(v.views) > 0 && v.summary.Fresh == v.summary.Nodes && (!v.target.live || v.summary.Accepting == v.summary.Nodes)
}

// meshView reads each cluster's nodes at most once per pass, and only when a gate asks.
type meshView struct {
	r     *IssuerApprovalReconciler
	ctx   context.Context
	now   time.Time
	local *trustprofile.Publication
	read  map[string]*clusterView
}

func (m *meshView) cluster(name string) *clusterView {
	if v, ok := m.read[name]; ok {
		return v
	}
	v := &clusterView{}
	m.read[name] = v
	reader, nodes, publication := m.r.reader(name), m.r.Cache, m.local
	if name != m.r.Options.LocalCluster {
		nodes = reader
	}
	switch {
	case reader == nil:
		v.err = errors.New("no peer API credentials")
	case name != m.r.Options.LocalCluster:
		if publication, v.err = m.r.readPublication(m.ctx, reader); v.err != nil {
			v.err = fmt.Errorf("read the publication: %w", v.err)
		}
	}
	if v.err == nil {
		v.target = publicationTarget(publication, m.now)
		v.views, v.err = m.r.readNodes(m.ctx, name, nodes, m.now)
	}
	v.summary = summarize(name, v.views, func(n nodeView) bool { return accepts(n, v.target) })
	if v.err != nil {
		v.summary.Message = strings.TrimSpace(v.summary.Message + " " + v.err.Error())
	}
	m.r.Metrics.Reports.WithLabelValues(name, "fresh").Set(float64(v.summary.Fresh))
	m.r.Metrics.Reports.WithLabelValues(name, "not_fresh").Set(float64(v.summary.Nodes - v.summary.Fresh))
	m.r.Metrics.Reports.WithLabelValues(name, "accepting").Set(float64(v.summary.Accepting))
	return v
}

// converged reports whether every node of every cluster converged, and names the first cluster that did not.
func (m *meshView) converged() (bool, string) {
	for _, c := range m.r.Options.Clusters {
		if v := m.cluster(c.Name); !v.converged() {
			return false, c.Name + ": " + v.summary.Message
		}
	}
	return true, ""
}

// trusts is the planner's mesh trust gate: ztunnel on every node of every cluster holds this issuer key of this
// cluster in its current checkpoint.
func (m *meshView) trusts(cluster, spki string) bool {
	domain := ""
	for _, c := range m.r.Options.Clusters {
		if c.Name == cluster {
			domain = c.TrustDomain
		}
	}
	if domain == "" {
		return false
	}
	for _, c := range m.r.Options.Clusters {
		v := m.cluster(c.Name)
		if v.err != nil || len(v.views) == 0 {
			return false
		}
		for _, n := range v.views {
			if !trusts(n, domain, spki) {
				return false
			}
		}
	}
	return true
}

// Reconcile is one arbiter pass. Order: promote a published pending slot; wait while a slot is pending; delete a
// slot that was never published, or the predecessor once every local node accepts the current generation; otherwise
// plan, and write the next generation into the free slot when every gate holds.
func (r *IssuerApprovalReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (result ctrl.Result, reconcileErr error) {
	ctx, cancel := context.WithTimeout(ctx, issuerApprovalPassTimeout)
	defer cancel()
	started := time.Now()
	attempt := r.attempt.Add(1)
	now := r.now()
	log := ctrl.LoggerFrom(ctx).WithValues("component", "issuer-approval-arbiter", "attempt", attempt, "enforcementAvailable", false)
	next := ctrl.Result{RequeueAfter: issuerApprovalPoll}
	outcome := "error"
	defer func() {
		if r.Metrics != nil {
			r.Metrics.Passes.WithLabelValues(outcome).Inc()
		}
		if reconcileErr != nil {
			log.Error(reconcileErr, "issuer approval pass failed", "stage", "reconcile", "elapsed", time.Since(started), "backoff", issuerApprovalPoll)
		}
	}()
	if err := r.Options.Validate(); err != nil {
		return ctrl.Result{}, err
	}
	if r.Client == nil || r.Reader == nil || r.Cache == nil || r.Metrics == nil {
		return ctrl.Result{}, errors.New("explicit writer, API reader, cache and metrics required")
	}
	record, err := r.record(ctx)
	if err != nil {
		return next, err
	}
	st, err := r.readState(ctx, record)
	if err != nil {
		return next, err
	}
	status := &api.IssuerApprovalStatus{}
	record.Status.DeepCopyInto(status)
	status.ObservedAt = &metav1.Time{Time: now}
	status.Current = ref(st.current, "")
	if old := record.Status.Current; old != nil && status.Current != nil && old.UID == status.Current.UID {
		status.Current.Reason = old.Reason
	}
	if st.pending == nil {
		if old := record.Status.Pending; old != nil && status.Current != nil && old.UID == status.Current.UID {
			status.Current.Reason = old.Reason
			log.Info("pending approval is published", "stage", "promote", "generation", status.Current.Generation, "slot", status.Current.Slot)
		}
		status.Pending = nil
	}

	mesh := &meshView{r: r, ctx: ctx, now: now, local: st.publication, read: map[string]*clusterView{}}
	localConverged := mesh.cluster(r.Options.LocalCluster).converged()

	var holds []trustprofile.Hold
	blocked, action := "", ""
	var actionErr error
	planned := false
	switch {
	case st.pending != nil:
		if created := st.pending.object.CreationTimestamp.Time; !created.IsZero() && now.Sub(created) > pendingPublishWarning {
			blocked = BlockPendingNotPublished
			holds = append(holds, trustprofile.Hold{Reason: blocked, Message: fmt.Sprintf("slot %s generation %d is not published after %s; see the issuer-profile producer log", st.pending.name, st.pending.generation(), pendingPublishWarning)})
		}
		log.Info("waiting for the producer to publish the pending approval", "stage", "publish-wait", "generation", st.pending.generation(), "slot", st.pending.name, "elapsed", time.Since(started))
	default:
		action, actionErr, blocked, holds = r.cleanSlots(ctx, st, localConverged, log)
		if action != "" || blocked != "" {
			break
		}
		planned = true
		plan, err := r.plan(ctx, st, status, now, mesh)
		if err != nil {
			blocked = BlockPlanFailed
			holds = append(holds, trustprofile.Hold{Reason: blocked, Message: err.Error()})
			break
		}
		holds = append(holds, plan.Holds...)
		if plan.Next == nil {
			break
		}
		free := ""
		for _, name := range r.Options.Slots {
			if st.slots[name].object == nil && free == "" {
				free = name
			}
		}
		meshConverged, why := mesh.converged()
		switch {
		case !meshConverged:
			blocked = BlockMeshNotConverged
			holds = append(holds, trustprofile.Hold{Reason: blocked, Message: fmt.Sprintf("generation %d (%s) waits until every node of every cluster reports fresh and accepts its cluster's generation; %s", plan.Next.Generation, plan.Reason, why)})
		case free == "":
			blocked = BlockNoFreeSlot
			holds = append(holds, trustprofile.Hold{Reason: blocked, Message: "both slots hold approvals"})
		default:
			s, err := r.writeSlot(ctx, free, plan, now)
			if err != nil {
				blocked, actionErr = BlockWriteRefused, err
				holds = append(holds, trustprofile.Hold{Reason: blocked, Message: err.Error()})
				break
			}
			action = "wrote"
			status.Pending = ref(&s, plan.Reason)
			log.Info("approval slot written; the producer publishes it next", "stage", "slot-write", "slot", free, "generation", s.generation(), "reason", plan.Reason, "expiresAt", s.approval.ExpiresAt, "elapsed", time.Since(started))
		}
	}
	for _, h := range holds {
		switch h.Reason {
		case trustprofile.HoldEvidenceRefused, trustprofile.HoldOverlapFull, trustprofile.HoldRootChanged, trustprofile.HoldRenewalWaits, trustprofile.HoldExpiresWithinMargin:
			if blocked == "" {
				blocked = h.Reason
			}
		}
	}
	r.writeStatus(status, st, mesh, holds, planned, localConverged, blocked, now)
	r.statusMetrics(st, status)
	if err := r.Client.Status().Update(ctx, &api.IssuerApproval{ObjectMeta: record.ObjectMeta, Status: *status}); err != nil {
		return next, errors.Join(actionErr, fmt.Errorf("update the IssuerApproval status: %w", err))
	}
	switch {
	case actionErr != nil:
		return next, actionErr
	case action != "":
		outcome = action
	case blocked != "":
		outcome = "held"
	default:
		outcome = "idle"
	}
	log.Info("issuer approval pass", "stage", "pass", "result", outcome, "phase", status.Phase, "blocked", blocked, "localConverged", localConverged, "elapsed", time.Since(started), "nextRetry", issuerApprovalPoll)
	return next, nil
}

func (r *IssuerApprovalReconciler) statusMetrics(st passState, status *api.IssuerApprovalStatus) {
	accepted := 0.0
	if st.publication != nil {
		accepted = float64(st.publication.AcceptedGeneration)
	}
	r.Metrics.Generation.WithLabelValues("accepted").Set(accepted)
	pending := 0.0
	if status.Pending != nil {
		pending = float64(status.Pending.Generation)
	}
	r.Metrics.Generation.WithLabelValues("pending").Set(pending)
	expiry := 0.0
	if st.accepted != nil {
		if at, err := time.Parse(time.RFC3339, st.accepted.ExpiresAt); err == nil {
			expiry = float64(at.Unix())
		}
	}
	r.Metrics.Expiry.Set(expiry)
	for _, p := range []string{api.ApprovalPending, api.ApprovalPublishing, api.ApprovalDistributing, api.ApprovalOverlapping, api.ApprovalConverged, api.ApprovalBlocked} {
		value := 0.0
		if p == status.Phase {
			value = 1
		}
		r.Metrics.Phase.WithLabelValues(p).Set(value)
	}
}

// cleanSlots deletes at most one slot that is neither current nor pending: at once when it was never published (a
// write whose record update was lost), otherwise only once every local node accepts the current generation, so no
// consumer still reads it. A ConfigMap with a slot name that the arbiter did not write is never deleted.
func (r *IssuerApprovalReconciler) cleanSlots(ctx context.Context, st passState, localConverged bool, log logr.Logger) (string, error, string, []trustprofile.Hold) {
	accepted := uint64(0)
	if st.publication != nil {
		accepted = st.publication.AcceptedGeneration
	}
	var holds []trustprofile.Hold
	action, blocked := "", ""
	var err error
	for _, name := range r.Options.Slots {
		s := st.slots[name]
		if s.object == nil || st.current != nil && st.current.name == name {
			continue
		}
		if s.invalid == notArbiterSlot {
			blocked = BlockForeignSlot
			holds = append(holds, trustprofile.Hold{Reason: blocked, Message: "ConfigMap " + name + " has a slot name but was not written by the arbiter; it is never deleted"})
			continue
		}
		neverPublished := s.generation() > accepted
		if action != "" || !neverPublished && !localConverged {
			continue
		}
		uid := s.object.UID
		err = r.Client.Delete(ctx, s.object, client.Preconditions{UID: &uid})
		if apierrors.IsNotFound(err) {
			err = nil
		}
		action = "deleted"
		result := "acknowledged"
		if err != nil {
			result = err.Error()
		}
		log.Info("approval slot deleted", "stage", "slot-delete", "slot", name, "generation", s.generation(), "neverPublished", neverPublished, "invalid", s.invalid, "result", result)
	}
	return action, err, blocked, holds
}

// plan reads every cluster's evidence and runs the pure planner, then checks the candidate exactly as the producer
// will, and the overlap invariant once more.
func (r *IssuerApprovalReconciler) plan(ctx context.Context, st passState, status *api.IssuerApprovalStatus, now time.Time, mesh *meshView) (trustprofile.Plan, error) {
	var rootCM corev1.ConfigMap
	if err := r.Reader.Get(ctx, r.key(r.Options.RootConfigMap), &rootCM); err != nil {
		return trustprofile.Plan{}, fmt.Errorf("read the mesh root ConfigMap: %w", err)
	}
	rootPEM := rootCM.Data["ca.crt"]
	root, err := trustprofile.ParseRoot(rootPEM, r.Options.RootPins, now)
	if err != nil {
		return trustprofile.Plan{}, err
	}
	evidence := map[string]trustprofile.Evidence{}
	identities := make([]trustprofile.ClusterIdentity, 0, len(r.Options.Clusters))
	for _, c := range r.Options.Clusters {
		identities = append(identities, trustprofile.ClusterIdentity{Name: c.Name, TrustDomain: c.TrustDomain})
		reader := r.reader(c.Name)
		if reader == nil {
			evidence[c.Name] = trustprofile.Evidence{Reason: "PeerNotConfigured", Message: "no peer API credentials for " + c.Name}
			continue
		}
		evidence[c.Name] = readIntermediate(ctx, reader, r.Options, c, root, now)
	}
	plan, err := trustprofile.PlanApproval(trustprofile.PlanInput{Now: now, LocalCluster: r.Options.LocalCluster, RootPins: r.Options.RootPins,
		RootPEM: rootPEM, Clusters: identities, Evidence: evidence, Previous: st.accepted, Generation: st.generation,
		Ledger: ledgerFromStatus(status), Force: st.published && st.current == nil, Horizon: r.Options.Horizon,
		RenewBefore: r.Options.RenewBefore, RetirementMargin: r.Options.RetirementMargin, MeshTrusts: mesh.trusts})
	if err != nil {
		return plan, err
	}
	status.Clusters = clusterStatus(r.Options, evidence, plan)
	if plan.Next == nil {
		return plan, nil
	}
	body, err := json.Marshal(plan.Next)
	if err != nil {
		return plan, err
	}
	if _, err := trustprofile.Validate(body, r.Options.RootPins, r.Options.LocalCluster, now); err != nil {
		return plan, fmt.Errorf("the producer would refuse generation %d: %w", plan.Next.Generation, err)
	}
	if err := trustprofile.CheckSuccession(st.accepted, plan.Next, plan.Ledger, now, r.Options.RetirementMargin, mesh.trusts); err != nil {
		return plan, err
	}
	return plan, nil
}

// writeSlot creates the next immutable approval, in the producer's canonical form, in a free slot.
func (r *IssuerApprovalReconciler) writeSlot(ctx context.Context, name string, plan trustprofile.Plan, now time.Time) (slot, error) {
	body, err := json.Marshal(plan.Next)
	if err != nil {
		return slot{}, err
	}
	valid, err := trustprofile.Validate(body, r.Options.RootPins, r.Options.LocalCluster, now)
	if err != nil {
		return slot{}, err
	}
	canonical, err := json.Marshal(valid.Approval)
	if err != nil {
		return slot{}, err
	}
	if err := ctx.Err(); err != nil {
		return slot{}, err
	}
	immutable := true
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Namespace: r.Options.Namespace, Name: name,
			Labels:      map[string]string{SlotLabel: "true", SlotGenerationLabel: strconv.FormatUint(valid.Approval.Generation, 10), "app.kubernetes.io/managed-by": "cmtc-controller"},
			Annotations: map[string]string{SlotReasonAnnotation: plan.Reason}},
		Immutable: &immutable,
		Data:      map[string]string{trustprofile.ApprovalKey: string(canonical)},
	}
	if err := r.Client.Create(ctx, cm); err != nil {
		return slot{}, fmt.Errorf("create slot %s: %w", name, err)
	}
	a := valid.Approval
	return slot{name: name, object: cm, approval: &a}, nil
}

func ledgerFromStatus(status *api.IssuerApprovalStatus) []trustprofile.IssuerRecord {
	var out []trustprofile.IssuerRecord
	for _, c := range status.Clusters {
		for _, i := range c.Issuers {
			rec := trustprofile.IssuerRecord{Cluster: c.Name, SPKISHA256: i.SPKISHA256, NotAfter: i.NotAfter.UTC(), SupersededBy: i.SupersededBy}
			if i.FirstCurrentAt != nil {
				rec.FirstCurrent = i.FirstCurrentAt.UTC()
			}
			if i.SupersededAt != nil {
				rec.Superseded = i.SupersededAt.UTC()
			}
			if d, err := time.ParseDuration(i.SPIRECAMaxDuration); err == nil {
				rec.SPIRECAMaxDuration = d
			}
			out = append(out, rec)
		}
	}
	return out
}

func stamp(t time.Time) *metav1.Time {
	if t.IsZero() {
		return nil
	}
	return &metav1.Time{Time: t}
}

func clusterStatus(o IssuerApprovalOptions, evidence map[string]trustprofile.Evidence, plan trustprofile.Plan) []api.ClusterApprovalStatus {
	byCluster := map[string][]api.IssuerRecord{}
	for _, rec := range plan.Ledger {
		out := api.IssuerRecord{SPKISHA256: rec.SPKISHA256, NotAfter: metav1.NewTime(rec.NotAfter), FirstCurrentAt: stamp(rec.FirstCurrent), SupersededAt: stamp(rec.Superseded), SupersededBy: rec.SupersededBy}
		if rec.SPIRECAMaxDuration > 0 {
			out.SPIRECAMaxDuration = rec.SPIRECAMaxDuration.String()
		}
		if at, ok := rec.RetireAfter(o.RetirementMargin); ok {
			out.RetireAfter = stamp(at)
		}
		byCluster[rec.Cluster] = append(byCluster[rec.Cluster], out)
	}
	out := make([]api.ClusterApprovalStatus, 0, len(o.Clusters))
	for _, c := range o.Clusters {
		ev := evidence[c.Name]
		s := api.ClusterApprovalStatus{Name: c.Name, TrustDomain: c.TrustDomain, Evidence: "Ready", Message: ev.Message, Current: plan.Current[c.Name], Issuers: byCluster[c.Name]}
		switch {
		case ev.Refused:
			s.Evidence, s.Message = "Refused", ev.Reason+": "+ev.Message
		case ev.Issuer == nil:
			s.Evidence, s.Message = "Unavailable", ev.Reason+": "+ev.Message
		}
		out = append(out, s)
	}
	return out
}

func condition(kind string, ok bool, reason, message string, now time.Time) metav1.Condition {
	status := metav1.ConditionFalse
	if ok {
		status = metav1.ConditionTrue
	}
	if len(message) > 32000 {
		message = message[:32000]
	}
	return metav1.Condition{Type: kind, Status: status, Reason: reason, Message: message, LastTransitionTime: metav1.NewTime(now)}
}

// writeStatus sets the node summaries, the phase and the conditions. EvidenceReady changes only on a pass that read
// the evidence.
func (r *IssuerApprovalReconciler) writeStatus(status *api.IssuerApprovalStatus, st passState, mesh *meshView, holds []trustprofile.Hold, planned, localConverged bool, blocked string, now time.Time) {
	nodes := make([]api.NodeSummary, 0, len(r.Options.Clusters))
	for _, c := range r.Options.Clusters {
		if v, ok := mesh.read[c.Name]; ok {
			nodes = append(nodes, v.summary)
			continue
		}
		for _, old := range status.Nodes {
			if old.Cluster == c.Name {
				nodes = append(nodes, old)
			}
		}
	}
	status.Nodes = nodes
	overlapping := false
	if st.accepted != nil {
		for _, c := range st.accepted.Clusters {
			overlapping = overlapping || len(c.Issuers) > 1
		}
	}
	switch {
	case status.Pending != nil:
		status.Phase = api.ApprovalPublishing
	case blocked != "":
		status.Phase = api.ApprovalBlocked
	case st.accepted == nil:
		status.Phase = api.ApprovalPending
	case !localConverged:
		status.Phase = api.ApprovalDistributing
	case overlapping:
		status.Phase = api.ApprovalOverlapping
	default:
		status.Phase = api.ApprovalConverged
	}
	var conditions []metav1.Condition
	if planned {
		var missing []string
		for _, h := range holds {
			if h.Reason == trustprofile.HoldEvidenceUnavailable || h.Reason == trustprofile.HoldEvidenceRefused {
				missing = append(missing, h.Cluster+": "+h.Message)
			}
		}
		reason := "AllClustersRead"
		if len(missing) > 0 {
			reason = "EvidenceMissing"
		}
		conditions = append(conditions, condition(ConditionEvidenceReady, len(missing) == 0, reason, strings.Join(missing, "; "), now))
	}
	local := mesh.read[r.Options.LocalCluster]
	nodesReason := "AllNodesAccept"
	if !localConverged {
		nodesReason = "NodesNotConverged"
	}
	conditions = append(conditions, condition(ConditionNodesConverged, localConverged, nodesReason,
		strings.TrimSpace(fmt.Sprintf("%d of %d local nodes report fresh, %d accept generation %d. %s", local.summary.Fresh, local.summary.Nodes, local.summary.Accepting, local.target.generation, local.summary.Message)), now))
	var text []string
	for _, h := range holds {
		text = append(text, strings.TrimSpace(h.Cluster+" "+h.Reason+": "+h.Message))
	}
	blockedReason := "NotBlocked"
	if blocked != "" {
		blockedReason = blocked
	}
	conditions = append(conditions, condition(ConditionBlocked, blocked != "", blockedReason, strings.Join(text, "; "), now))
	for _, c := range conditions {
		meta.SetStatusCondition(&status.Conditions, c)
	}
}

// SetupWithManager adds the arbiter as a leader-elected runnable: it runs only on the leader, like the producer.
func (r *IssuerApprovalReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := r.Options.Validate(); err != nil {
		return err
	}
	if r.Client == nil || r.Reader == nil || r.Cache == nil || r.Metrics == nil {
		return errors.New("explicit writer, API reader, cache and metrics required")
	}
	return mgr.Add(&issuerApprovalRunner{reconciler: r})
}

type issuerApprovalRunner struct{ reconciler *IssuerApprovalReconciler }

func (*issuerApprovalRunner) NeedLeaderElection() bool { return true }

// Start runs a pass every issuerApprovalPoll; a failed pass is logged by Reconcile and retried on the next tick.
func (w *issuerApprovalRunner) Start(ctx context.Context) error {
	for {
		_, _ = w.reconciler.Reconcile(ctx, ctrl.Request{})
		if ctx.Err() != nil {
			return nil
		}
		timer := time.NewTimer(issuerApprovalPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = (*issuerApprovalRunner)(nil)
