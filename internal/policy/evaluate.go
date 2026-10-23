package policy

import (
	"fmt"
	"slices"
	"strings"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

const EnrollmentLabel = "io.cilium/mtls-enabled"

type Decision string

const (
	Selected   Decision = "selected"
	Excluded   Decision = "excluded"
	Platform   Decision = "platform"
	Unselected Decision = "unselected"
)

// Compiled validates once and evaluates current namespace objects, never stale names.
type Compiled struct {
	spec             api.NamespaceMTLSPolicySpec
	include, exclude []labels.Selector
}

func Compile(spec api.NamespaceMTLSPolicySpec) (*Compiled, error) {
	if spec.Enforcement.Mode != "Observe" {
		return nil, fmt.Errorf("only enforcement.mode=Observe is implemented")
	}
	if spec.Enrollment.SelectionMode != "AllEligible" && spec.Enrollment.SelectionMode != "MatchSelectors" {
		return nil, fmt.Errorf("selectionMode must be AllEligible or MatchSelectors")
	}
	if spec.Enrollment.SelectionMode == "MatchSelectors" && len(spec.Inclusions.NamespaceSelectors) == 0 {
		return nil, fmt.Errorf("MatchSelectors requires inclusion selectors")
	}
	if spec.Enrollment.SelectionMode == "AllEligible" && len(spec.Inclusions.NamespaceSelectors) != 0 {
		return nil, fmt.Errorf("AllEligible cannot also specify inclusion selectors")
	}
	include, err := compileSelectors(spec.Inclusions.NamespaceSelectors)
	if err != nil {
		return nil, fmt.Errorf("inclusions: %w", err)
	}
	exclude, err := compileSelectors(spec.Exclusions.NamespaceSelectors)
	if err != nil {
		return nil, fmt.Errorf("exclusions: %w", err)
	}
	return &Compiled{spec: spec, include: include, exclude: exclude}, nil
}

func compileSelectors(in []metav1.LabelSelector) ([]labels.Selector, error) {
	var out []labels.Selector
	for _, s := range in {
		if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
			return nil, fmt.Errorf("empty selectors are ambiguous")
		}
		parsed, err := metav1.LabelSelectorAsSelector(&s)
		if err != nil {
			return nil, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

func IsPlatform(ns corev1.Namespace, additional []string) bool {
	if slices.Contains(additional, ns.Name) {
		return true
	}
	for _, prefix := range []string{"kube-", "openshift", "cilium-", "cmtc-"} {
		if strings.HasPrefix(ns.Name, prefix) {
			return true
		}
	}
	return slices.Contains([]string{"cert-manager", "trust-manager", "spire", "istio-system", "linkerd"}, ns.Name) ||
		ns.Labels["security.cmtc.io/platform-protected"] == "true" ||
		ns.Labels["openshift.io/run-level"] != ""
}

func matches(selectors []labels.Selector, set labels.Set) bool {
	for _, s := range selectors {
		if s.Matches(set) {
			return true
		}
	}
	return false
}

func (c *Compiled) Evaluate(ns corev1.Namespace) Decision {
	if IsPlatform(ns, c.spec.AdditionalPlatformNamespaces) {
		return Platform
	}
	if slices.Contains(c.spec.Exclusions.Namespaces, ns.Name) || matches(c.exclude, labels.Set(ns.Labels)) {
		return Excluded
	}
	if c.spec.Enrollment.SelectionMode == "AllEligible" || matches(c.include, labels.Set(ns.Labels)) {
		return Selected
	}
	return Unselected
}
