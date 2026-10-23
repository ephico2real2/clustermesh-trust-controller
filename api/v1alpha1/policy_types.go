// Package v1alpha1 defines CMTC's experimental observation API.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var GroupVersion = schema.GroupVersion{Group: "security.cmtc.io", Version: "v1alpha1"}

func AddToScheme(s *runtime.Scheme) error {
	s.AddKnownTypes(GroupVersion, &NamespaceMTLSPolicy{}, &NamespaceMTLSPolicyList{})
	metav1.AddToGroupVersion(s, GroupVersion)
	return nil
}

type Enrollment struct {
	SelectionMode string `json:"selectionMode"`
}

type Selectors struct {
	NamespaceSelectors []metav1.LabelSelector `json:"namespaceSelectors,omitempty"`
}

type Exclusions struct {
	Namespaces         []string               `json:"namespaces,omitempty"`
	NamespaceSelectors []metav1.LabelSelector `json:"namespaceSelectors,omitempty"`
}

type Enforcement struct {
	// Only Observe is implemented. The CRD rejects Strict/label-writing modes.
	Mode string `json:"mode"`
}

type NamespaceMTLSPolicySpec struct {
	Enrollment                   Enrollment  `json:"enrollment"`
	Inclusions                   Selectors   `json:"inclusions,omitempty"`
	Exclusions                   Exclusions  `json:"exclusions,omitempty"`
	AdditionalPlatformNamespaces []string    `json:"additionalPlatformNamespaces,omitempty"`
	Enforcement                  Enforcement `json:"enforcement"`
}

type NamespaceMTLSPolicyStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Selected           int32              `json:"selected"`
	Excluded           int32              `json:"excluded"`
	Platform           int32              `json:"platform"`
	Unselected         int32              `json:"unselected"`
	Labeled            int32              `json:"labeled"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// NamespaceMTLSPolicy is cluster scoped. Exactly one active policy is supported.
type NamespaceMTLSPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              NamespaceMTLSPolicySpec   `json:"spec"`
	Status            NamespaceMTLSPolicyStatus `json:"status,omitempty"`
}

type NamespaceMTLSPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NamespaceMTLSPolicy `json:"items"`
}

func (p *NamespaceMTLSPolicy) DeepCopy() *NamespaceMTLSPolicy {
	if p == nil {
		return nil
	}
	out := *p
	out.ObjectMeta = *p.ObjectMeta.DeepCopy()
	out.Spec.Inclusions.NamespaceSelectors = copySelectors(p.Spec.Inclusions.NamespaceSelectors)
	out.Spec.Exclusions.NamespaceSelectors = copySelectors(p.Spec.Exclusions.NamespaceSelectors)
	out.Spec.Exclusions.Namespaces = append([]string(nil), p.Spec.Exclusions.Namespaces...)
	out.Spec.AdditionalPlatformNamespaces = append([]string(nil), p.Spec.AdditionalPlatformNamespaces...)
	out.Status.Conditions = append([]metav1.Condition(nil), p.Status.Conditions...)
	return &out
}

func copySelectors(in []metav1.LabelSelector) []metav1.LabelSelector {
	if in == nil {
		return nil
	}
	out := make([]metav1.LabelSelector, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
}

func (p *NamespaceMTLSPolicy) DeepCopyObject() runtime.Object {
	if p == nil {
		return nil
	}
	return p.DeepCopy()
}

func (p *NamespaceMTLSPolicyList) DeepCopyObject() runtime.Object {
	if p == nil {
		return nil
	}
	out := *p
	out.ListMeta = *p.ListMeta.DeepCopy()
	out.Items = make([]NamespaceMTLSPolicy, len(p.Items))
	for i := range p.Items {
		out.Items[i] = *p.Items[i].DeepCopy()
	}
	return &out
}
