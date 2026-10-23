package policy

import (
	"testing"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSelectionAndPrecedence(t *testing.T) {
	spec := api.NamespaceMTLSPolicySpec{Enrollment: api.Enrollment{SelectionMode: "MatchSelectors"}, Enforcement: api.Enforcement{Mode: "Observe"}, Inclusions: api.Selectors{NamespaceSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"lob": "alpha"}}, {MatchLabels: map[string]string{"mnemonic": "delta", "env": "prod"}}}}, Exclusions: api.Exclusions{Namespaces: []string{"legacy"}}}
	c, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   Decision
	}{
		{"alpha", map[string]string{"lob": "alpha"}, Selected},
		{"delta", map[string]string{"mnemonic": "delta", "env": "prod"}, Selected},
		{"and-is-required", map[string]string{"mnemonic": "delta"}, Unselected},
		{"legacy", map[string]string{"lob": "alpha"}, Excluded},
		{"kube-system", map[string]string{"lob": "alpha"}, Platform},
		{"openshift-authentication", map[string]string{"lob": "alpha"}, Platform},
		{"marked", map[string]string{"lob": "alpha", "security.cmtc.io/platform-protected": "true"}, Platform},
		{"intent-is-not-selection", map[string]string{EnrollmentLabel: "true"}, Unselected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: tc.name, Labels: tc.labels}}
			if got := c.Evaluate(ns); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	// Explicit exclusions cannot override platform classification.
	spec.Exclusions.Namespaces = append(spec.Exclusions.Namespaces, "kube-system")
	c, err = Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if c.Evaluate(corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}}) != Platform {
		t.Fatal("platform precedence lost")
	}
}

func TestValidationAndAllEligible(t *testing.T) {
	base := api.NamespaceMTLSPolicySpec{Enrollment: api.Enrollment{SelectionMode: "AllEligible"}, Enforcement: api.Enforcement{Mode: "Observe"}}
	c, err := Compile(base)
	if err != nil {
		t.Fatal(err)
	}
	if c.Evaluate(corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app"}}) != Selected {
		t.Fatal("AllEligible failed")
	}
	for _, tc := range []struct {
		name   string
		change func(*api.NamespaceMTLSPolicySpec)
	}{
		{"strict-not-implemented", func(s *api.NamespaceMTLSPolicySpec) { s.Enforcement.Mode = "Strict" }},
		{"ambiguous-mode", func(s *api.NamespaceMTLSPolicySpec) { s.Enrollment.SelectionMode = "" }},
		{"missing-selectors", func(s *api.NamespaceMTLSPolicySpec) { s.Enrollment.SelectionMode = "MatchSelectors" }},
		{"empty-selector", func(s *api.NamespaceMTLSPolicySpec) { s.Exclusions.NamespaceSelectors = []metav1.LabelSelector{{}} }},
		{"invalid-expression", func(s *api.NamespaceMTLSPolicySpec) {
			s.Exclusions.NamespaceSelectors = []metav1.LabelSelector{{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "lob", Operator: "invalid"}}}}
		}},
		{"conflicting-inclusions", func(s *api.NamespaceMTLSPolicySpec) {
			s.Inclusions.NamespaceSelectors = []metav1.LabelSelector{{MatchLabels: map[string]string{"lob": "alpha"}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := base
			tc.change(&spec)
			if _, err := Compile(spec); err == nil {
				t.Fatal("unsafe/ambiguous policy accepted")
			}
		})
	}
}

func TestExclusionSelectorsAndRecreatedNamespace(t *testing.T) {
	spec := api.NamespaceMTLSPolicySpec{Enrollment: api.Enrollment{SelectionMode: "AllEligible"}, Enforcement: api.Enforcement{Mode: "Observe"}, Exclusions: api.Exclusions{NamespaceSelectors: []metav1.LabelSelector{{MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "exempt", Operator: metav1.LabelSelectorOpExists}}}}}}
	c, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	ns := corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "app", UID: "old", Labels: map[string]string{"exempt": ""}}}
	if c.Evaluate(ns) != Excluded {
		t.Fatal("exclusion ignored")
	}
	ns.UID = "new"
	ns.Labels = nil
	if c.Evaluate(ns) != Selected {
		t.Fatal("stale namespace decision reused")
	}
}
