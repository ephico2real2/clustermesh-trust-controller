package main

import (
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// The controller hands leadership over at once on a graceful stop and uses
// the leader timing the issuer-profile publication is sized for. Node agents
// do not take part in leader election.
func TestManagerOptionsLeaderElection(t *testing.T) {
	scheme := runtime.NewScheme()
	c := managerOptions(scheme, "controller", "", ":8080", ":8081")
	if !c.LeaderElection || !c.LeaderElectionReleaseOnCancel || c.LeaderElectionID != "cmtc-controller.security.cmtc.io" {
		t.Fatalf("controller leader election = %v, release on cancel = %v, ID %q", c.LeaderElection, c.LeaderElectionReleaseOnCancel, c.LeaderElectionID)
	}
	if c.LeaseDuration == nil || *c.LeaseDuration != controller.LeaderLeaseDuration ||
		c.RenewDeadline == nil || *c.RenewDeadline != controller.LeaderRenewDeadline ||
		c.RetryPeriod == nil || *c.RetryPeriod != controller.LeaderRetryPeriod {
		t.Fatal("controller leader timing is not the timing the publication is sized for")
	}
	n := managerOptions(scheme, "node", "node-a", ":8080", ":8081")
	if n.LeaderElection || n.LeaderElectionReleaseOnCancel || len(n.Cache.ByObject) != 2 {
		t.Fatalf("node mode leader election = %v, release = %v, cache selectors = %d", n.LeaderElection, n.LeaderElectionReleaseOnCancel, len(n.Cache.ByObject))
	}
}

// The node agent caches only its node's Pods and only enrolled namespaces: a cluster of 5,000 Pods costs each agent
// the Pods of one node.
func TestNodeCacheIsNodeScoped(t *testing.T) {
	n := managerOptions(runtime.NewScheme(), "node", "node-a", ":8080", ":8081")
	for obj, sel := range n.Cache.ByObject {
		switch obj.(type) {
		case *corev1.Pod:
			if sel.Field == nil || sel.Field.String() != "spec.nodeName=node-a" || sel.Label != nil {
				t.Fatalf("Pod cache selector = field %v, label %v", sel.Field, sel.Label)
			}
		case *corev1.Namespace:
			if sel.Label == nil || sel.Label.String() != "io.cilium/mtls-enabled=true" || sel.Field != nil {
				t.Fatalf("Namespace cache selector = field %v, label %v", sel.Field, sel.Label)
			}
		default:
			t.Fatalf("unexpected cached type %T", obj)
		}
	}
}
