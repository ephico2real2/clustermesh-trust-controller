package controller

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Producer and leader-election timing. A publication is valid for
// trustprofile.MaxLease and republished once less than
// trustprofile.RenewBefore remains, so a stopping leader leaves at least
// RenewBefore - issuerProfilePoll - issuerProfilePassTimeout of validity. A
// waiting successor publishes within LeaderLeaseDuration + LeaderRetryPeriod
// (the leader crashed and never released its lease) plus its first pass. The
// publication must outlive that handover: otherwise every node's issuer
// profile expires and ztunnel drains all workload TLS. A graceful leader
// releases the lease at once (LeaderElectionReleaseOnCancel).
const (
	issuerProfilePoll        = 5 * time.Second
	issuerProfilePassTimeout = 4 * time.Second
	LeaderLeaseDuration      = 8 * time.Second
	LeaderRenewDeadline      = 5 * time.Second
	LeaderRetryPeriod        = 1 * time.Second
)

type IssuerProfileOptions struct {
	Source, Output       client.ObjectKey
	SourceUID, OutputUID types.UID
	MinimumGeneration    uint64
	RootPins             []string
	LocalCluster         string
}

const issuerProfileOptionsInvalid = "explicit distinct source/output names and UIDs, cluster, positive generation and root pins required"

func (o IssuerProfileOptions) Validate() error {
	if o.Source.Namespace == "" || o.Source.Name == "" || o.Output.Namespace != o.Source.Namespace || o.Output == o.Source || o.SourceUID == "" || o.SourceUID == o.OutputUID {
		return errors.New(issuerProfileOptionsInvalid)
	}
	return o.validateOutput()
}

// ValidateFollowed checks the options of a producer that publishes the approval the issuer approval arbiter names
// on each pass (ADR-012). A fixed source is refused; each followed source is checked with Validate.
func (o IssuerProfileOptions) ValidateFollowed() error {
	if o.Source != (client.ObjectKey{}) || o.SourceUID != "" || o.Output.Namespace == "" {
		return errors.New("a followed producer has no fixed source and needs the output namespace")
	}
	return o.validateOutput()
}

func (o IssuerProfileOptions) validateOutput() error {
	if o.Output.Name == "" || o.OutputUID == "" || o.MinimumGeneration == 0 || !trustprofile.ClusterValid(o.LocalCluster) || len(o.RootPins) == 0 || len(o.RootPins) > 4 {
		return errors.New(issuerProfileOptionsInvalid)
	}
	seen := map[string]bool{}
	for _, pin := range o.RootPins {
		if !trustprofile.PinValid(pin) || seen[pin] {
			return errors.New("invalid/duplicate root pin")
		}
		seen[pin] = true
	}
	return nil
}

// Output writes use resourceVersion from a direct API read; no broad creates or
// cached source reads. The optional controller lives beside PolicyReconciler.
type IssuerProfileReconciler struct {
	client.Client
	Reader  client.Reader
	Options IssuerProfileOptions
	// Follow, when set, names the source of each pass (the issuer approval arbiter's FollowedSource) and
	// Options names none. An error ends the pass without a write.
	Follow  func(context.Context, *trustprofile.Publication) (client.ObjectKey, types.UID, error)
	Metrics *trustprofile.Metrics
	Now     func() time.Time
	attempt atomic.Uint64
}

func (r *IssuerProfileReconciler) validate() error {
	if r.Follow != nil {
		return r.Options.ValidateFollowed()
	}
	return r.Options.Validate()
}

func (r *IssuerProfileReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
func (r *IssuerProfileReconciler) Reconcile(ctx context.Context, _ ctrl.Request) (requeue ctrl.Result, reconcileErr error) {
	ctx, cancel := context.WithTimeout(ctx, issuerProfilePassTimeout)
	defer cancel()
	started := time.Now()
	attempt := r.attempt.Add(1)
	now := r.now()
	log := ctrl.LoggerFrom(ctx).WithValues("component", "issuer-profile-producer", "attempt", attempt, "source", r.Options.Source, "output", r.Options.Output, "enforcementAvailable", false)
	if deadline, ok := ctx.Deadline(); ok {
		log = log.WithValues("deadline", deadline.UTC())
	}
	defer func() {
		if reconcileErr != nil {
			log.Error(reconcileErr, "issuer-profile pass failed", "stage", "reconcile", "elapsed", time.Since(started), "backoff", issuerProfilePoll)
		}
	}()
	next := ctrl.Result{RequeueAfter: issuerProfilePoll}
	if err := r.validate(); err != nil {
		return ctrl.Result{}, err
	}
	if r.Reader == nil || r.Client == nil || r.Metrics == nil {
		return ctrl.Result{}, errors.New("explicit reader/writer/metrics required")
	}
	var out corev1.ConfigMap
	if err := r.Reader.Get(ctx, r.Options.Output, &out); err != nil {
		log.Error(err, "pre-created output unavailable", "stage", "output-read", "elapsed", time.Since(started), "backoff", issuerProfilePoll)
		return next, err
	}
	if out.ResourceVersion == "" || out.UID != r.Options.OutputUID || out.DeletionTimestamp != nil || out.Labels[trustprofile.OutputLabel] != "true" || len(out.OwnerReferences) > 0 || len(out.BinaryData) > 0 || out.Immutable != nil && *out.Immutable {
		return next, errors.New("foreign/deleting/immutable output rejected")
	}
	for key := range out.Data {
		if key != trustprofile.DataKey {
			return next, errors.New("unexpected output data key; preserving object")
		}
	}
	var previous *trustprofile.Publication
	if raw := out.Data[trustprofile.DataKey]; raw != "" {
		var err error
		previous, err = trustprofile.DecodePublication([]byte(raw))
		if err != nil {
			return next, fmt.Errorf("preserving corrupt output: %w", err)
		}
		if previous.OutputUID != string(out.UID) || previous.ProducerCluster != r.Options.LocalCluster {
			return next, errors.New("output publication ownership differs")
		}
	} else if out.Annotations[trustprofile.InitializedAnnotation] == "true" {
		return next, errors.New("initialized output was cleared; explicit repair required")
	}
	if previous != nil && previous.Sequence == ^uint64(0) {
		return next, errors.New("publication sequence exhausted")
	}
	opts := r.Options
	if r.Follow != nil {
		key, uid, err := r.Follow(ctx, previous)
		if err == nil {
			opts.Source, opts.SourceUID = key, uid
			err = opts.Validate()
		}
		if err != nil {
			return next, fmt.Errorf("no followed approval source: %w", err)
		}
		log = log.WithValues("followedSource", opts.Source, "followedSourceUID", opts.SourceUID)
	}
	p := trustprofile.Publication{SchemaVersion: trustprofile.SchemaVersion, Sequence: 1, State: "withdrawn", ProducerCluster: opts.LocalCluster, OutputUID: string(out.UID), ExpectedSourceUID: string(opts.SourceUID), Source: trustprofile.Source{Namespace: opts.Source.Namespace, Name: opts.Source.Name, UID: string(opts.SourceUID)}, PublishedAt: trustprofile.Stamp(now), ValidUntil: trustprofile.Stamp(now)}
	if previous != nil {
		p.Sequence = previous.Sequence + 1
		p.AcceptedGeneration = previous.AcceptedGeneration
		p.AcceptedSourceUID = previous.AcceptedSourceUID
		p.AcceptedApprovalDigest = previous.AcceptedApprovalDigest
	}
	var source corev1.ConfigMap
	sourceErr := r.Reader.Get(ctx, opts.Source, &source)
	switch {
	case apierrors.IsNotFound(sourceErr):
		p.Reason = "SourceDeleted"
	case sourceErr != nil:
		p.Reason = "SourceUnavailable"
	default:
		r.Metrics.SourceChecked.Set(float64(now.Unix()))
		p.Source.UID = string(source.UID)
		p.Source.ResourceVersion = source.ResourceVersion
		switch {
		case source.DeletionTimestamp != nil:
			p.Reason = "SourceDeleted"
		case source.UID != opts.SourceUID:
			p.Reason = "SourceUIDMismatch"
		case source.ResourceVersion == "":
			p.Reason = "SourceInvalid"
		case source.Immutable == nil || !*source.Immutable || len(source.BinaryData) > 0 || len(source.Data) != 1:
			p.Reason = "SourceInvalid"
		default:
			valid, err := trustprofile.Validate([]byte(source.Data[trustprofile.ApprovalKey]), opts.RootPins, opts.LocalCluster, now)
			if err != nil {
				p.Reason = "SourceInvalid"
				var invalid *trustprofile.ValidationError
				if errors.As(err, &invalid) {
					p.Reason = invalid.Reason
				}
				log.Error(err, "approval validation rejected", "stage", "validate", "elapsed", time.Since(started), "generation", p.AcceptedGeneration, "backoff", issuerProfilePoll)
			} else {
				p.Source.Generation = valid.Approval.Generation
				switch {
				case valid.Approval.Generation < opts.MinimumGeneration || valid.Approval.Generation < p.AcceptedGeneration:
					p.Reason = "GenerationRollback"
				case previous != nil && valid.Approval.Generation == p.AcceptedGeneration && (previous.AcceptedApprovalDigest != valid.Digest || previous.AcceptedSourceUID != string(source.UID)):
					p.Reason = "GenerationRollback"
				default:
					// Immutable data and UID pinning prevent content replacement. Recheck exact
					// API object UID/RV/deletion immediately before composing publication;
					// this cannot create a multi-object Kubernetes transaction.
					var latest corev1.ConfigMap
					err = r.Reader.Get(ctx, opts.Source, &latest)
					if err != nil {
						if apierrors.IsNotFound(err) {
							p.Reason = "SourceDeleted"
						} else {
							p.Reason = "SourceUnavailable"
						}
						sourceErr = err
					} else if latest.DeletionTimestamp != nil {
						p.Reason = "SourceDeleted"
					} else if latest.UID != source.UID {
						p.Reason = "SourceUIDMismatch"
						p.Source.UID = string(latest.UID)
						p.Source.ResourceVersion = latest.ResourceVersion
					} else if latest.ResourceVersion != source.ResourceVersion {
						p.Reason = "SourceChanged"
					} else {
						p.State = "published"
						p.Reason = "Validated"
						p.AcceptedGeneration = valid.Approval.Generation
						p.AcceptedSourceUID = string(source.UID)
						p.AcceptedApprovalDigest = valid.Digest
						p.Approval = &valid.Approval
						p.ApprovalDigest = valid.Digest
						until := now.Add(trustprofile.MaxLease)
						if valid.Until.Before(until) {
							until = valid.Until
						}
						p.ValidUntil = trustprofile.Stamp(until)
					}
				}
			}
		}
	}
	if sourceErr != nil && !apierrors.IsNotFound(sourceErr) {
		log.Error(sourceErr, "source read unavailable", "stage", "source-read", "elapsed", time.Since(started), "backoff", issuerProfilePoll)
	}
	result := "rejected"
	if p.State == "published" {
		result = "accepted"
	} else if p.Reason == "SourceUnavailable" || p.Reason == "SourceDeleted" {
		result = "unavailable"
	}
	r.Metrics.Validation.WithLabelValues(result).Inc()
	log.Info("public issuer approval evaluated", "stage", "validate", "result", result, "state", p.State, "reason", p.Reason, "generation", p.AcceptedGeneration, "sourceUID", p.Source.UID, "elapsed", time.Since(started), "nextRetry", issuerProfilePoll)
	unchanged := false
	if previous != nil && p.State == previous.State && p.Reason == previous.Reason && p.ExpectedSourceUID == previous.ExpectedSourceUID && p.Source == previous.Source && p.AcceptedGeneration == previous.AcceptedGeneration && p.ApprovalDigest == previous.ApprovalDigest {
		if p.State == "withdrawn" {
			unchanged = true
		} else {
			expiry, _ := time.Parse(time.RFC3339, previous.ValidUntil)
			unchanged = now.Add(trustprofile.RenewBefore).Before(expiry)
		}
	}
	if unchanged {
		if sourceErr != nil && !apierrors.IsNotFound(sourceErr) {
			return next, sourceErr
		}
		return next, nil
	}
	body, err := trustprofile.Encode(p)
	if err != nil {
		return next, err
	}
	desired := out.DeepCopy()
	desired.Data = map[string]string{trustprofile.DataKey: string(body)}
	if desired.Annotations == nil {
		desired.Annotations = map[string]string{}
	}
	desired.Annotations[trustprofile.InitializedAnnotation] = "true"
	if reflect.DeepEqual(out.Data, desired.Data) && reflect.DeepEqual(out.Annotations, desired.Annotations) {
		return next, nil
	}
	// Update uses the directly fetched resourceVersion. Cancellation/timeout may
	// have committed server-side: a retry re-reads and does not double-publish.
	if err := ctx.Err(); err != nil {
		return next, err
	}
	err = r.Update(ctx, desired)
	outcome := "acknowledged"
	if err != nil {
		outcome = "error"
	}
	r.Metrics.Writes.WithLabelValues(p.State, outcome).Inc()
	if err != nil {
		log.Error(err, "publication write not acknowledged", "stage", "publish", "state", p.State, "reason", p.Reason, "elapsed", time.Since(started), "backoff", issuerProfilePoll)
		return next, errors.Join(sourceErr, err)
	}
	if p.State == "published" {
		until, _ := time.Parse(time.RFC3339, p.ValidUntil)
		r.Metrics.PublishedUntil.Set(float64(until.Unix()))
	} else {
		r.Metrics.PublishedUntil.Set(0)
	}
	log.Info("public issuer mapping publication acknowledged; consumption unverified", "stage", "publish", "state", p.State, "reason", p.Reason, "sequence", p.Sequence, "generation", p.AcceptedGeneration, "publicationBytesSHA256", trustprofile.SHA(body), "approvalDigest", p.ApprovalDigest, "elapsed", time.Since(started), "nextRetry", issuerProfilePoll)
	if sourceErr != nil && !apierrors.IsNotFound(sourceErr) {
		return next, sourceErr
	}
	return next, nil
}
func (r *IssuerProfileReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := r.validate(); err != nil {
		return err
	}
	if r.Reader == nil || r.Client == nil || r.Metrics == nil {
		return errors.New("explicit API reader, writer and metrics required")
	}
	// Direct exact GET polling avoids granting list/watch over unrelated ConfigMaps.
	return mgr.Add(&issuerProfileRunner{reconciler: r})
}

type issuerProfileRunner struct{ reconciler *IssuerProfileReconciler }

func (*issuerProfileRunner) NeedLeaderElection() bool { return true }
func (w *issuerProfileRunner) Start(ctx context.Context) error {
	for {
		_, err := w.reconciler.Reconcile(ctx, ctrl.Request{})
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			ctrl.LoggerFrom(ctx).Error(err, "issuer-profile pass failed", "stage", "reconcile", "backoff", issuerProfilePoll, "enforcementAvailable", false)
		}
		timer := time.NewTimer(issuerProfilePoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// Compile-time interfaces keep this runnable in the existing controller manager.
var _ interface {
	Start(context.Context) error
	NeedLeaderElection() bool
} = (*issuerProfileRunner)(nil)
