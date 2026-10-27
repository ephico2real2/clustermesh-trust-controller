package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/measurement"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Measurement tells the eBPF measurement loader which Pods of this node to measure, and logs each change of the
// plane's readiness. The agent holds the API token and no capability; the loader (cmd/cmtc-measure) holds CAP_BPF
// and CAP_NET_ADMIN and no API token (ADR-005). The metrics come from Collector, which reads the loader's snapshot.
type Measurement struct {
	// Client reads the manager's cache, which cmd/cmtc limits to this node's Pods and to enrolled namespaces.
	Client client.Reader
	Node   string
	// DesiredDir is the volume that the agent writes and the loader reads.
	DesiredDir string
	Collector  *measurement.Collector
	Log        logr.Logger
	Interval   time.Duration

	written []byte // the desired list last written
	syncErr string
	ready   bool
	reason  string
}

// Sync builds the desired list from the cache and writes it when it changed.
func (m *Measurement) Sync(ctx context.Context) error {
	d, err := m.desired(ctx)
	if err == nil {
		err = m.write(d)
	}
	m.Collector.SetDesired(d.Pods, err)
	return err
}

func (m *Measurement) desired(ctx context.Context) (measurement.Desired, error) {
	var namespaces corev1.NamespaceList
	if err := m.Client.List(ctx, &namespaces, client.MatchingLabels{measurement.EnrollmentLabel: "true"}); err != nil {
		return measurement.Desired{}, fmt.Errorf("list enrolled namespaces: %w", err)
	}
	var pods corev1.PodList
	if err := m.Client.List(ctx, &pods); err != nil {
		return measurement.Desired{}, fmt.Errorf("list the node's Pods: %w", err)
	}
	enrolled := make(map[string]bool, len(namespaces.Items))
	for _, ns := range namespaces.Items {
		enrolled[ns.Name] = true
	}
	return measurement.Desired{Version: measurement.ExchangeVersion, Node: m.Node,
		Pods: DesiredPods(pods.Items, m.Node, enrolled), NodeAddresses: NodeAddresses(pods.Items, m.Node)}, nil
}

func (m *Measurement) write(d measurement.Desired) error {
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if bytes.Equal(b, m.written) {
		return nil
	}
	if err := measurement.WriteFileAtomic(m.DesiredDir, measurement.DesiredFile, d); err != nil {
		return fmt.Errorf("write the desired list: %w", err)
	}
	m.written = b
	return nil
}

// DesiredPods returns the Pods to measure, sorted by UID: on this node, in an enrolled namespace, in the Pod network
// (the Cilium fork refuses to enroll a hostNetwork Pod), and Pending or Running. A terminating Pod is measured until
// it stops, but it is not required.
func DesiredPods(pods []corev1.Pod, node string, enrolled map[string]bool) []measurement.DesiredPod {
	out := []measurement.DesiredPod{}
	for _, p := range pods {
		if p.Spec.NodeName != node || p.Spec.HostNetwork || !enrolled[p.Namespace] || p.UID == "" {
			continue
		}
		if p.Status.Phase != corev1.PodPending && p.Status.Phase != corev1.PodRunning {
			continue
		}
		out = append(out, measurement.DesiredPod{UID: string(p.UID), Namespace: p.Namespace,
			Required: p.Status.Phase == corev1.PodRunning && p.DeletionTimestamp == nil})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// NodeAddresses returns the IP addresses of the Pending and Running Pods of this node, enrolled or not, sorted and
// without duplicates. A hostNetwork Pod gives the node's own addresses. A DNS server at one of them is same_node.
func NodeAddresses(pods []corev1.Pod, node string) []string {
	seen := map[netip.Addr]bool{}
	for _, p := range pods {
		if p.Spec.NodeName != node || (p.Status.Phase != corev1.PodPending && p.Status.Phase != corev1.PodRunning) {
			continue
		}
		for _, ip := range p.Status.PodIPs {
			if addr, err := netip.ParseAddr(ip.IP); err == nil && addr.Zone() == "" {
				seen[addr.Unmap()] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for addr := range seen {
		out = append(out, addr.String())
	}
	sort.Strings(out)
	return out
}

// Start writes the desired list every Interval and logs each change of readiness, and of the error that stops the
// list, once.
func (m *Measurement) Start(ctx context.Context) error {
	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	m.reason = "starting"
	for {
		err := m.Sync(ctx)
		if msg := errorText(err); msg != m.syncErr {
			if err != nil {
				m.Log.Error(err, "measurement desired list not written; the loader keeps the previous one", "stage", "desired")
			} else {
				m.Log.Info("measurement desired list written again", "stage", "desired")
			}
			m.syncErr = msg
		}
		_, _, ready, reason := m.Collector.Evaluate()
		if ready != m.ready || reason != m.reason {
			m.Log.Info("measurement readiness changed", "stage", "readiness", "ready", ready, "reason", reason,
				"enforcementAvailable", false)
			m.ready, m.reason = ready, reason
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// NeedLeaderElection is false: every node agent measures its own node.
func (m *Measurement) NeedLeaderElection() bool { return false }
