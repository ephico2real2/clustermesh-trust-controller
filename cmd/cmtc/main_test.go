package main

import (
	"testing"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/controller"
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
	if n.LeaderElection || n.LeaderElectionReleaseOnCancel || len(n.Cache.ByObject) != 1 {
		t.Fatalf("node mode leader election = %v, release = %v, cache selectors = %d", n.LeaderElection, n.LeaderElectionReleaseOnCancel, len(n.Cache.ByObject))
	}
}
