package spireregistrar

import (
	"context"
	"errors"
	"fmt"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/policy"
	"reflect"
	"time"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Snapshot struct {
	Entries []*types.Entry
	objects map[string]client.Object
}

func (s *Snapshot) remember(o client.Object) {
	s.objects[fmt.Sprintf("%T/%s/%s", o, o.GetNamespace(), o.GetName())] = o.DeepCopyObject().(client.Object)
}
func (s *Snapshot) Recheck(ctx context.Context, r client.Reader) error {
	for _, old := range s.objects {
		fresh := reflect.New(reflect.TypeOf(old).Elem()).Interface().(client.Object)
		if err := r.Get(ctx, client.ObjectKeyFromObject(old), fresh); err != nil {
			return err
		}
		if fresh.GetUID() != old.GetUID() || fresh.GetResourceVersion() != old.GetResourceVersion() || fresh.GetDeletionTimestamp() != nil {
			return errors.New("Kubernetes incarnation/revision changed during registration")
		}
	}
	return ctx.Err()
}

type Source struct {
	Reader  client.Reader
	Options Options
}

func (s Source) Collect(ctx context.Context, now time.Time) (*Snapshot, error) {
	o := s.Options
	if err := o.Validate(); err != nil {
		return nil, err
	}
	out := &Snapshot{objects: map[string]client.Object{}}
	get := func(key client.ObjectKey, obj client.Object) error {
		if err := s.Reader.Get(ctx, key, obj); err != nil {
			return err
		}
		if obj.GetDeletionTimestamp() != nil {
			return errors.New("source object is deleting")
		}
		out.remember(obj)
		return nil
	}
	var cluster corev1.Namespace
	if err := get(client.ObjectKey{Name: "kube-system"}, &cluster); err != nil {
		return nil, err
	}
	if cluster.UID != o.ClusterUID {
		return nil, errors.New("cluster UID pin mismatch")
	}
	daemon := func(a DaemonApproval) (*appsv1.DaemonSet, error) {
		var ns corev1.Namespace
		var sa corev1.ServiceAccount
		var d appsv1.DaemonSet
		if err := get(client.ObjectKey{Name: a.Namespace}, &ns); err != nil {
			return nil, err
		}
		if err := get(client.ObjectKey{Namespace: a.Namespace, Name: a.ServiceAccount}, &sa); err != nil {
			return nil, err
		}
		if err := get(client.ObjectKey{Namespace: a.Namespace, Name: a.Name}, &d); err != nil {
			return nil, err
		}
		if ns.UID != a.NamespaceUID || sa.UID != a.ServiceAccountUID || d.UID != a.UID {
			return nil, errors.New("daemon namespace/service-account/controller UID pin mismatch")
		}
		return &d, nil
	}
	agentDaemon, err := daemon(o.Agent)
	if err != nil {
		return nil, err
	}
	delegateDaemon, err := daemon(o.Delegate)
	if err != nil {
		return nil, err
	}
	listPods := func(namespace string) ([]corev1.Pod, error) {
		var list corev1.PodList
		if err := s.Reader.List(ctx, &list, client.InNamespace(namespace), client.Limit(129)); err != nil {
			return nil, err
		}
		if list.Continue != "" || len(list.Items) > 128 {
			return nil, errors.New("bounded registrar Pod inventory exceeded")
		}
		return list.Items, nil
	}
	agents, err := listPods(o.Agent.Namespace)
	if err != nil {
		return nil, err
	}
	byNode := map[string]*corev1.Pod{}
	for i := range agents {
		p := &agents[i]
		if !daemonPod(p, agentDaemon, o.Agent) {
			continue
		}
		if byNode[p.Spec.NodeName] != nil {
			return nil, errors.New("multiple current SPIRE agents on a node; refusing ambiguous alias")
		}
		byNode[p.Spec.NodeName] = p
	}
	desired := map[string]*types.Entry{}
	add := func(p *corev1.Pod, ns *corev1.Namespace, sa *corev1.ServiceAccount, isDelegate bool) error {
		if !currentPod(p) {
			return nil
		}
		agent := byNode[p.Spec.NodeName]
		if agent == nil {
			return errors.New("scheduled node has no exact current SPIRE agent")
		}
		var node corev1.Node
		if err := get(client.ObjectKey{Name: p.Spec.NodeName}, &node); err != nil {
			return err
		}
		entries, err := Desired(o, Input{Namespace: ns, Account: sa, Pod: p, Node: &node, Agent: agent, AgentDaemon: agentDaemon, DelegateDaemon: delegateDaemon}, isDelegate, now)
		if err != nil {
			return err
		}
		out.remember(p)
		out.remember(agent)
		for _, entry := range entries {
			desired[entry.Id] = entry
		}
		if len(desired) > 128 {
			return errors.New("bounded registrar entry inventory exceeded")
		}
		return nil
	}
	for _, approval := range o.Namespaces {
		var ns corev1.Namespace
		if err := get(client.ObjectKey{Name: approval.Name}, &ns); err != nil {
			return nil, err
		}
		if ns.UID != approval.UID {
			return nil, errors.New("approved namespace UID changed")
		}
		// A removed label, platform classification, or explicit exclusion produces
		// no desired rows. Reconciliation deletes previously owned rows first.
		selected := ns.Labels["io.cilium/mtls-enabled"] == "true"
		if policy.IsPlatform(ns, nil) {
			selected = false
		}
		for _, n := range o.ExcludedNamespaces {
			if n == ns.Name {
				selected = false
			}
		}
		if !selected {
			continue
		}
		accounts := map[string]*corev1.ServiceAccount{}
		for name, id := range approval.ServiceAccounts {
			var sa corev1.ServiceAccount
			if err := get(client.ObjectKey{Namespace: ns.Name, Name: name}, &sa); err != nil {
				return nil, err
			}
			if sa.UID != id {
				return nil, errors.New("approved workload service-account UID changed")
			}
			accounts[name] = &sa
		}
		pods, err := listPods(ns.Name)
		if err != nil {
			return nil, err
		}
		for i := range pods {
			p := &pods[i]
			sa := accounts[p.Spec.ServiceAccountName]
			if sa == nil || p.Spec.HostNetwork || p.Spec.HostPID {
				continue
			}
			if err := add(p, &ns, sa, false); err != nil {
				return nil, err
			}
		}
	}
	var delegateNS corev1.Namespace
	var delegateSA corev1.ServiceAccount
	if err := get(client.ObjectKey{Name: o.Delegate.Namespace}, &delegateNS); err != nil {
		return nil, err
	}
	if err := get(client.ObjectKey{Namespace: o.Delegate.Namespace, Name: o.Delegate.ServiceAccount}, &delegateSA); err != nil {
		return nil, err
	}
	pods, err := listPods(o.Delegate.Namespace)
	if err != nil {
		return nil, err
	}
	for i := range pods {
		p := &pods[i]
		if !daemonPod(p, delegateDaemon, o.Delegate) {
			continue
		}
		if err := add(p, &delegateNS, &delegateSA, true); err != nil {
			return nil, err
		}
	}
	for _, entry := range desired {
		out.Entries = append(out.Entries, entry)
	}
	entryOrder(out.Entries)
	if err := out.Recheck(ctx, s.Reader); err != nil {
		return nil, err
	}
	return out, nil
}
