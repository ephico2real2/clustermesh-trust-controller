package controller

import (
	"context"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/policy"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type PolicyReconciler struct {
	client.Client
	Metrics *telemetry.Metrics
}

func (r *PolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var policies api.NamespaceMTLSPolicyList
	if err := r.List(ctx, &policies); err != nil {
		return ctrl.Result{}, err
	}
	if len(policies.Items) == 0 {
		r.Metrics.SetDecisions(map[string]int{}, 0)
		return ctrl.Result{}, nil
	}
	var current api.NamespaceMTLSPolicy
	if err := r.Get(ctx, req.NamespacedName, &current); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	before := current.DeepCopy()
	current.Status = api.NamespaceMTLSPolicyStatus{ObservedGeneration: current.Generation, Conditions: current.Status.Conditions}
	condition := func(kind string, status metav1.ConditionStatus, reason, message string) {
		meta.SetStatusCondition(&current.Status.Conditions, metav1.Condition{Type: kind, Status: status, Reason: reason, Message: message, ObservedGeneration: current.Generation})
	}
	condition("EnforcementVerified", metav1.ConditionUnknown, "CiliumIntegrationUnavailable", "Observe mode cannot verify or enable workload mTLS; namespace labels are never changed.")
	compiled, err := policy.Compile(current.Spec)
	counts := map[string]int{}
	switch {
	case len(policies.Items) != 1:
		condition("EvaluationReady", metav1.ConditionFalse, "PolicyConflict", "Exactly one cluster-scoped policy is supported; all evaluation is blocked until the conflict is resolved.")
	case err != nil:
		condition("EvaluationReady", metav1.ConditionFalse, "InvalidPolicy", err.Error())
	default:
		var namespaces corev1.NamespaceList
		if err := r.List(ctx, &namespaces); err != nil {
			return ctrl.Result{}, err
		}
		for _, ns := range namespaces.Items {
			counts[string(compiled.Evaluate(ns))]++
			if ns.Labels[policy.EnrollmentLabel] == "true" {
				current.Status.Labeled++
			}
		}
		current.Status.Selected = int32(counts["selected"])
		current.Status.Excluded = int32(counts["excluded"])
		current.Status.Platform = int32(counts["platform"])
		current.Status.Unselected = int32(counts["unselected"])
		condition("EvaluationReady", metav1.ConditionTrue, "Observed", "Policy evaluated against current namespaces; no enrollment or protection is asserted.")
		r.Metrics.Evaluations.Inc()
	}
	if err := r.Status().Patch(ctx, &current, client.MergeFrom(before)); err != nil {
		return ctrl.Result{}, err
	}
	r.Metrics.SetDecisions(counts, int(current.Status.Labeled))
	return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
}

func (r *PolicyReconciler) allPolicies(ctx context.Context, _ client.Object) []ctrl.Request {
	var list api.NamespaceMTLSPolicyList
	if err := r.List(ctx, &list); err != nil {
		ctrl.LoggerFrom(ctx).Error(err, "listing policies for namespace event")
		return nil
	}
	var out []ctrl.Request
	for _, p := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&p)})
	}
	return out
}

func (r *PolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.NamespaceMTLSPolicy{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&api.NamespaceMTLSPolicy{}, handler.EnqueueRequestsFromMapFunc(r.allPolicies), builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.allPolicies)).
		Complete(r)
}
