// Package spireregistrar manages exact, expiring registrations inside the SPIRE server boundary.
package spireregistrar

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/policy"
)

type NamespaceApproval struct {
	Name            string                `json:"name"`
	UID             ktypes.UID            `json:"uid"`
	ServiceAccounts map[string]ktypes.UID `json:"serviceAccounts"`
}

type DaemonApproval struct {
	Namespace         string     `json:"namespace"`
	NamespaceUID      ktypes.UID `json:"namespaceUID"`
	Name              string     `json:"name"`
	UID               ktypes.UID `json:"uid"`
	ServiceAccount    string     `json:"serviceAccount"`
	ServiceAccountUID ktypes.UID `json:"serviceAccountUID"`
	Container         string     `json:"container"`
	Image             string     `json:"image"`
}

type Options struct {
	ClusterName        string              `json:"clusterName"`
	ClusterUID         ktypes.UID          `json:"clusterUID"`
	TrustDomain        string              `json:"trustDomain"`
	InstallationID     string              `json:"installationID"`
	Agent              DaemonApproval      `json:"agent"`
	Delegate           DaemonApproval      `json:"delegate"`
	Namespaces         []NamespaceApproval `json:"namespaces"`
	ExcludedNamespaces []string            `json:"excludedNamespaces"`
}

func dns(s string) bool { return s != "" && len(validation.IsDNS1123Subdomain(s)) == 0 }
func uid(s ktypes.UID) bool {
	id, err := uuid.Parse(string(s))
	return err == nil && id != uuid.Nil && id.String() == string(s)
}
func (d DaemonApproval) valid() bool {
	parts := strings.Split(d.Image, "@sha256:")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return false
	}
	if _, err := hex.DecodeString(parts[1]); err != nil {
		return false
	}
	return dns(d.Namespace) && uid(d.NamespaceUID) && dns(d.Name) && uid(d.UID) && dns(d.ServiceAccount) && uid(d.ServiceAccountUID) && dns(d.Container)
}
func (o Options) Validate() error {
	if !dns(o.ClusterName) || !dns(o.TrustDomain) || strings.ToLower(o.TrustDomain) != o.TrustDomain || !uid(o.ClusterUID) || !uid(ktypes.UID(o.InstallationID)) || !o.Agent.valid() || !o.Delegate.valid() || len(o.Namespaces) > 16 {
		return errors.New("invalid explicit registrar installation pins")
	}
	seen := map[string]bool{}
	for _, n := range o.Namespaces {
		if !dns(n.Name) || !uid(n.UID) || seen[n.Name] || n.Name == o.Agent.Namespace || n.Name == o.Delegate.Namespace || len(n.ServiceAccounts) == 0 || len(n.ServiceAccounts) > 16 {
			return errors.New("invalid or duplicate namespace/service-account approval")
		}
		seen[n.Name] = true
		for name, id := range n.ServiceAccounts {
			if !dns(name) || !uid(id) {
				return errors.New("invalid service-account pin")
			}
		}
	}
	return nil
}
func (o Options) Hint() string {
	return "cmtc-registrar/v1/" + string(o.ClusterUID) + "/" + o.InstallationID
}

type Input struct {
	Namespace      *corev1.Namespace
	Account        *corev1.ServiceAccount
	Pod            *corev1.Pod
	Node           *corev1.Node
	Agent          *corev1.Pod
	AgentDaemon    *appsv1.DaemonSet
	DelegateDaemon *appsv1.DaemonSet // nil for ordinary workloads
}

func controlledBy(p *corev1.Pod, d *appsv1.DaemonSet) bool {
	owner := metav1.GetControllerOf(p)
	return owner != nil && owner.APIVersion == "apps/v1" && owner.Kind == "DaemonSet" && owner.UID == d.UID && owner.Name == d.Name
}
func currentPod(p *corev1.Pod) bool {
	return p != nil && uid(p.UID) && p.DeletionTimestamp == nil && p.Spec.NodeName != "" && (p.Status.Phase == corev1.PodPending || p.Status.Phase == corev1.PodRunning) && p.Annotations[corev1.MirrorPodAnnotationKey] == ""
}
func daemonPod(p *corev1.Pod, d *appsv1.DaemonSet, approval DaemonApproval) bool {
	if !currentPod(p) || d == nil || d.UID != approval.UID || d.DeletionTimestamp != nil || d.Namespace != approval.Namespace || d.Name != approval.Name || p.Namespace != d.Namespace || p.Spec.ServiceAccountName != approval.ServiceAccount || !controlledBy(p, d) {
		return false
	}
	found := false
	for _, c := range p.Spec.Containers {
		if c.Name == approval.Container {
			found = c.Image == approval.Image
		}
	}
	return found
}

// Desired uses exact API objects. Namespace and service-account approvals are
// independent administrative pins; an Observe decision or label is insufficient.
// A per-agent-incarnation PSAT alias supplies the Node UID binding that the
// workload k8s plugin's node-name selector alone cannot supply.
func Desired(o Options, in Input, delegate bool, now time.Time) ([]*types.Entry, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if in.Namespace == nil || in.Account == nil || in.Node == nil || !currentPod(in.Pod) || !daemonPod(in.Agent, in.AgentDaemon, o.Agent) || !uid(in.Node.UID) || in.Node.DeletionTimestamp != nil || in.Pod.Spec.NodeName != in.Node.Name || in.Agent.Spec.NodeName != in.Node.Name || in.Namespace.Name != in.Pod.Namespace || in.Namespace.DeletionTimestamp != nil || in.Account.Namespace != in.Pod.Namespace || in.Account.Name != in.Pod.Spec.ServiceAccountName || in.Account.DeletionTimestamp != nil {
		return nil, errors.New("stale or incomplete workload/agent incarnation")
	}
	if delegate {
		if in.Namespace.Name != o.Delegate.Namespace || in.Namespace.UID != o.Delegate.NamespaceUID || in.Account.UID != o.Delegate.ServiceAccountUID || !daemonPod(in.Pod, in.DelegateDaemon, o.Delegate) {
			return nil, errors.New("delegate does not match exact daemon approval")
		}
	} else {
		approved := false
		for _, a := range o.Namespaces {
			if a.Name == in.Namespace.Name && a.UID == in.Namespace.UID && a.ServiceAccounts[in.Account.Name] == in.Account.UID {
				approved = true
			}
		}
		if !approved || in.Namespace.Labels[policy.EnrollmentLabel] != "true" || policy.IsPlatform(*in.Namespace, nil) || in.Pod.Spec.HostNetwork || in.Pod.Spec.HostPID {
			return nil, errors.New("workload namespace/service account is not explicitly enrolled")
		}
		for _, excluded := range o.ExcludedNamespaces {
			if excluded == in.Namespace.Name {
				return nil, errors.New("namespace is excluded")
			}
		}
	}
	aliasPath := "/cmtc/agents/" + string(in.Node.UID) + "/" + string(in.Agent.UID)
	id := func(path string) *types.SPIFFEID { return &types.SPIFFEID{TrustDomain: o.TrustDomain, Path: path} }
	mk := func(role string, nsUID, podUID ktypes.UID, path, parent string, sels []*types.Selector) *types.Entry {
		binding, _ := json.Marshal([]string{o.InstallationID, string(o.ClusterUID), string(nsUID), string(in.Node.UID), string(in.Agent.UID), string(podUID), role})
		return &types.Entry{Id: uuid.NewSHA1(uuid.NameSpaceURL, binding).String(), SpiffeId: id(path), ParentId: id(parent), Selectors: sels, X509SvidTtl: 120, ExpiresAt: now.Add(90 * time.Second).Unix(), Hint: o.Hint()}
	}
	sel := func(kind, value string) *types.Selector { return &types.Selector{Type: kind, Value: value} }
	alias := mk("agent", o.Agent.NamespaceUID, in.Agent.UID, aliasPath, "/spire/server", []*types.Selector{
		sel("k8s_psat", "cluster:"+o.ClusterName), sel("k8s_psat", "agent_ns:"+o.Agent.Namespace), sel("k8s_psat", "agent_sa:"+o.Agent.ServiceAccount), sel("k8s_psat", "agent_pod_uid:"+string(in.Agent.UID)), sel("k8s_psat", "agent_node_name:"+in.Node.Name), sel("k8s_psat", "agent_node_uid:"+string(in.Node.UID)),
	})
	path := "/ns/" + in.Pod.Namespace + "/sa/" + in.Pod.Spec.ServiceAccountName
	role := "workload"
	if delegate {
		path = "/ztunnel-proxy"
		role = "delegate"
	}
	workload := mk(role, in.Namespace.UID, in.Pod.UID, path, aliasPath, []*types.Selector{sel("k8s", "ns:"+in.Pod.Namespace), sel("k8s", "sa:"+in.Pod.Spec.ServiceAccountName), sel("k8s", "pod-uid:"+string(in.Pod.UID)), sel("k8s", "node-name:"+in.Node.Name)})
	return []*types.Entry{alias, workload}, nil
}

func entryOrder(entries []*types.Entry) {
	sort.Slice(entries, func(i, j int) bool {
		a, b := entries[i].ParentId.Path == "/spire/server", entries[j].ParentId.Path == "/spire/server"
		if a != b {
			return a
		}
		return entries[i].Id < entries[j].Id
	})
}
