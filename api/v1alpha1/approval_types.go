package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// Approval arbiter phases (ADR-012). Exactly one is current.
const (
	// ApprovalPending: no approval yet; the arbiter waits for the evidence of every cluster.
	ApprovalPending = "Pending"
	// ApprovalPublishing: a new approval slot exists and the producer has not published it yet.
	ApprovalPublishing = "Publishing"
	// ApprovalDistributing: the current generation is published and not every local node accepts it yet.
	ApprovalDistributing = "Distributing"
	// ApprovalOverlapping: every local node accepts the current generation and a cluster still has two issuers.
	ApprovalOverlapping = "Overlapping"
	// ApprovalConverged: every local node accepts the current generation, one issuer per cluster, nothing is due.
	ApprovalConverged = "Converged"
	// ApprovalBlocked: a change is needed and a gate refuses it. The last approval stays until it expires.
	ApprovalBlocked = "Blocked"
)

// ApprovalRef names one immutable approval slot ConfigMap.
type ApprovalRef struct {
	Slot       string      `json:"slot"`
	UID        string      `json:"uid"`
	Generation uint64      `json:"generation"`
	Digest     string      `json:"digest,omitempty"`
	ExpiresAt  metav1.Time `json:"expiresAt"`
	Reason     string      `json:"reason,omitempty"`
}

// IssuerRecord is the arbiter's durable observation of one issuer key. A lost record is rebuilt from the next pass,
// which only delays a retirement.
type IssuerRecord struct {
	SPKISHA256 string      `json:"spkiSHA256"`
	NotAfter   metav1.Time `json:"notAfter"`
	// FirstCurrentAt is the first pass that read this key as the cluster's current intermediate.
	FirstCurrentAt *metav1.Time `json:"firstCurrentAt,omitempty"`
	// SupersededAt is the first pass that read another key as current. Zero while this key is current.
	SupersededAt *metav1.Time `json:"supersededAt,omitempty"`
	// SupersededBy is the key cert-manager issued next; every node of every cluster must trust it first.
	SupersededBy string `json:"supersededBy,omitempty"`
	// SPIRECAMaxDuration is the largest SPIRE CA lifetime approver-policy allowed while this key was superseded.
	SPIRECAMaxDuration string `json:"spireCAMaxDuration,omitempty"`
	// RetireAfter is SupersededAt + SPIRECAMaxDuration + the retirement margin: no SPIRE CA under this key is live then.
	RetireAfter *metav1.Time `json:"retireAfter,omitempty"`
}

// NodeSummary counts the reports of one cluster's nodes.
type NodeSummary struct {
	Cluster string `json:"cluster"`
	Nodes   int32  `json:"nodes"`
	// Fresh reports changed their heartbeat within the report age the arbiter allows, by the arbiter's own clock.
	Fresh int32 `json:"fresh"`
	// Accepting reports name ztunnel's acceptance of the current local generation (local cluster only).
	Accepting int32  `json:"accepting"`
	Message   string `json:"message,omitempty"`
}

type ClusterApprovalStatus struct {
	Name        string `json:"name"`
	TrustDomain string `json:"trustDomain"`
	// Evidence is Ready, Unavailable or Refused.
	Evidence string         `json:"evidence"`
	Message  string         `json:"message,omitempty"`
	Current  string         `json:"current,omitempty"`
	Issuers  []IssuerRecord `json:"issuers,omitempty"`
}

type IssuerApprovalStatus struct {
	Phase      string                  `json:"phase,omitempty"`
	ObservedAt *metav1.Time            `json:"observedAt,omitempty"`
	Current    *ApprovalRef            `json:"current,omitempty"`
	Pending    *ApprovalRef            `json:"pending,omitempty"`
	Clusters   []ClusterApprovalStatus `json:"clusters,omitempty"`
	Nodes      []NodeSummary           `json:"nodes,omitempty"`
	Conditions []metav1.Condition      `json:"conditions,omitempty"`
}

// IssuerApproval is the arbiter's report and durable record (ADR-012). The CMTC controller creates one, named by
// IssuerApprovalName, in its namespace, and is its only writer. It has no spec: the administrator approves the
// long-lived identities in the controller's configuration (Helm values).
type IssuerApproval struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            IssuerApprovalStatus `json:"status,omitempty"`
}

type IssuerApprovalList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []IssuerApproval `json:"items"`
}

// IssuerApprovalName is the name of the one IssuerApproval object.
const IssuerApprovalName = "cmtc"

// Node report states.
const (
	PinsUnchanged   = "Unchanged"
	PinsWritten     = "Written"
	PinsReadOnly    = "ReadOnly"
	PinsAbsent      = "Absent"
	PinsInvalid     = "Invalid"
	PinsWriteFailed = "WriteFailed"

	ZtunnelAccepted   = "Accepted"
	ZtunnelNotCurrent = "NotCurrent"
	ZtunnelAbsent     = "Absent"
	ZtunnelInvalid    = "Invalid"
)

// PinsReport is what the node agent read back from the node's issuer pins file after its last write.
type PinsReport struct {
	State string `json:"state"`
	// SHA256 is the digest of the file bytes as read back.
	SHA256     string   `json:"sha256,omitempty"`
	RootSHA256 []string `json:"rootSHA256,omitempty"`
	Message    string   `json:"message,omitempty"`
}

type TrustedIssuer struct {
	TrustDomain string `json:"trustDomain"`
	SPKISHA256  string `json:"spkiSHA256"`
}

// ZtunnelReport is read from ztunnel's durable issuer-profile checkpoint. ztunnel commits a publication before it
// acknowledges it, and it receives publications only from the node's Cilium agent, which serves only the approval it
// verified: a Validated, current checkpoint is the acceptance of both.
type ZtunnelReport struct {
	State              string          `json:"state"`
	Observation        string          `json:"observation,omitempty"`
	AcceptedGeneration uint64          `json:"acceptedGeneration,omitempty"`
	ApprovalDigest     string          `json:"approvalDigest,omitempty"`
	LoadedRootSHA256   []string        `json:"loadedRootSHA256,omitempty"`
	TrustedIssuers     []TrustedIssuer `json:"trustedIssuers,omitempty"`
	Message            string          `json:"message,omitempty"`
}

type NodeTrustReportStatus struct {
	Cluster string `json:"cluster"`
	// ObservedAt is the node agent's heartbeat. The arbiter does not compare it with its own clock: it counts a report
	// as fresh only when it saw ObservedAt change recently.
	ObservedAt metav1.Time        `json:"observedAt"`
	Pins       PinsReport         `json:"pins"`
	Ztunnel    ZtunnelReport      `json:"ztunnel"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// NodeTrustReport is cluster scoped and named after its node. Only that node's CMTC node agent may write it: a
// ValidatingAdmissionPolicy compares the name with the node its ServiceAccount token is bound to.
type NodeTrustReport struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Status            NodeTrustReportStatus `json:"status,omitempty"`
}

type NodeTrustReportList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeTrustReport `json:"items"`
}

func copyConditions(in []metav1.Condition) []metav1.Condition {
	if in == nil {
		return nil
	}
	out := make([]metav1.Condition, len(in))
	for i := range in {
		in[i].DeepCopyInto(&out[i])
	}
	return out
}

func copyTime(in *metav1.Time) *metav1.Time {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

func (r *ApprovalRef) deepCopy() *ApprovalRef {
	if r == nil {
		return nil
	}
	out := *r
	r.ExpiresAt.DeepCopyInto(&out.ExpiresAt)
	return &out
}

func (in *IssuerApprovalStatus) DeepCopyInto(out *IssuerApprovalStatus) {
	*out = *in
	out.ObservedAt = copyTime(in.ObservedAt)
	out.Current = in.Current.deepCopy()
	out.Pending = in.Pending.deepCopy()
	if in.Clusters != nil {
		out.Clusters = make([]ClusterApprovalStatus, len(in.Clusters))
		for i, c := range in.Clusters {
			out.Clusters[i] = c
			if c.Issuers != nil {
				out.Clusters[i].Issuers = make([]IssuerRecord, len(c.Issuers))
				for j, r := range c.Issuers {
					out.Clusters[i].Issuers[j] = r
					r.NotAfter.DeepCopyInto(&out.Clusters[i].Issuers[j].NotAfter)
					out.Clusters[i].Issuers[j].FirstCurrentAt = copyTime(r.FirstCurrentAt)
					out.Clusters[i].Issuers[j].SupersededAt = copyTime(r.SupersededAt)
					out.Clusters[i].Issuers[j].RetireAfter = copyTime(r.RetireAfter)
				}
			}
		}
	}
	out.Nodes = append([]NodeSummary(nil), in.Nodes...)
	out.Conditions = copyConditions(in.Conditions)
}

func (a *IssuerApproval) DeepCopy() *IssuerApproval {
	if a == nil {
		return nil
	}
	out := *a
	out.ObjectMeta = *a.ObjectMeta.DeepCopy()
	a.Status.DeepCopyInto(&out.Status)
	return &out
}

func (a *IssuerApproval) DeepCopyObject() runtime.Object {
	if a == nil {
		return nil
	}
	return a.DeepCopy()
}

func (l *IssuerApprovalList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := *l
	out.ListMeta = *l.ListMeta.DeepCopy()
	out.Items = make([]IssuerApproval, len(l.Items))
	for i := range l.Items {
		out.Items[i] = *l.Items[i].DeepCopy()
	}
	return &out
}

func (in *NodeTrustReportStatus) DeepCopyInto(out *NodeTrustReportStatus) {
	*out = *in
	in.ObservedAt.DeepCopyInto(&out.ObservedAt)
	out.Pins.RootSHA256 = append([]string(nil), in.Pins.RootSHA256...)
	out.Ztunnel.LoadedRootSHA256 = append([]string(nil), in.Ztunnel.LoadedRootSHA256...)
	out.Ztunnel.TrustedIssuers = append([]TrustedIssuer(nil), in.Ztunnel.TrustedIssuers...)
	out.Conditions = copyConditions(in.Conditions)
}

func (r *NodeTrustReport) DeepCopy() *NodeTrustReport {
	if r == nil {
		return nil
	}
	out := *r
	out.ObjectMeta = *r.ObjectMeta.DeepCopy()
	r.Status.DeepCopyInto(&out.Status)
	return &out
}

func (r *NodeTrustReport) DeepCopyObject() runtime.Object {
	if r == nil {
		return nil
	}
	return r.DeepCopy()
}

func (l *NodeTrustReportList) DeepCopyObject() runtime.Object {
	if l == nil {
		return nil
	}
	out := *l
	out.ListMeta = *l.ListMeta.DeepCopy()
	out.Items = make([]NodeTrustReport, len(l.Items))
	for i := range l.Items {
		out.Items[i] = *l.Items[i].DeepCopy()
	}
	return &out
}
