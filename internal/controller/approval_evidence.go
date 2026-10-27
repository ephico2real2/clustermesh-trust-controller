package controller

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The public cert-manager objects the arbiter reads. cert-manager's Go types are not a dependency: the fields used
// are read from unstructured objects and checked exactly.
var (
	certificateGVK  = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "Certificate"}
	requestGVK      = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "CertificateRequest"}
	clusterIssuerGV = schema.GroupVersionKind{Group: "cert-manager.io", Version: "v1", Kind: "ClusterIssuer"}
	policyGVK       = schema.GroupVersionKind{Group: "policy.cert-manager.io", Version: "v1alpha1", Kind: "CertificateRequestPolicy"}
	nodeGVK         = schema.GroupVersionKind{Version: "v1", Kind: "Node"}
)

var (
	upstreamAuthority = regexp.MustCompile(`UpstreamAuthority\s+"cert-manager"`)
	issuerName        = regexp.MustCompile(`(?m)^\s*issuer_name\s*=\s*"([^"]*)"\s*$`)
)

func object(gvk schema.GroupVersionKind) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(gvk)
	return u
}

func unavailable(reason string, err error) trustprofile.Evidence {
	return trustprofile.Evidence{Reason: reason, Message: err.Error()}
}

func refused(reason, message string) trustprofile.Evidence {
	return trustprofile.Evidence{Refused: true, Reason: reason, Message: message}
}

func readFailure(kind string, err error) trustprofile.Evidence {
	if apierrors.IsNotFound(err) {
		return unavailable(kind+"NotFound", err)
	}
	return unavailable(kind+"Unavailable", err)
}

func conditionTrue(u *unstructured.Unstructured, kind string) bool {
	conditions, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
	for _, c := range conditions {
		m, _ := c.(map[string]any)
		if m["type"] == kind && m["status"] == "True" {
			return true
		}
	}
	return false
}

// readIntermediate reads one cluster's SPIRE intermediate from public objects only; no Secret is read. It ports
// intermediate_evidence of scripts/lab/issuer-profile/publish_issuers.py: the approved Certificate (by UID) is a Ready
// CA from the mesh root issuer; the CertificateRequest of its current revision is owned by it, approved, issued by the
// same issuer and holds exactly the certificate the status names; the ClusterIssuer signs from the Certificate's
// Secret; SPIRE's server.conf requests its CA from that ClusterIssuer. A contradiction of an approved identity is
// refused; a read that fails or an issuance in progress is unavailable.
func readIntermediate(ctx context.Context, reader client.Reader, o IssuerApprovalOptions, c ApprovalCluster, root *x509.Certificate, now time.Time) trustprofile.Evidence {
	cert := object(certificateGVK)
	if err := reader.Get(ctx, client.ObjectKey{Namespace: o.CertManagerNamespace, Name: c.Certificate}, cert); err != nil {
		return readFailure("Certificate", err)
	}
	if cert.GetUID() != c.CertificateUID {
		return refused("CertificateUIDMismatch", fmt.Sprintf("Certificate %s/%s has UID %s, approved %s", o.CertManagerNamespace, c.Certificate, cert.GetUID(), c.CertificateUID))
	}
	if cert.GetDeletionTimestamp() != nil {
		return refused("CertificateDeleting", "the approved Certificate is being deleted")
	}
	ref, _, _ := unstructured.NestedMap(cert.Object, "spec", "issuerRef")
	isCA, _, _ := unstructured.NestedBool(cert.Object, "spec", "isCA")
	secret, _, _ := unstructured.NestedString(cert.Object, "spec", "secretName")
	wantRef := map[string]any{"name": o.RootIssuer, "kind": "ClusterIssuer", "group": "cert-manager.io"}
	if !isCA || secret == "" || !reflect.DeepEqual(ref, wantRef) {
		return refused("CertificateNotFromRoot", "the approved Certificate is not a CA issued by the mesh root ClusterIssuer "+o.RootIssuer)
	}
	revision, found, err := unstructured.NestedInt64(cert.Object, "status", "revision")
	notAfter, _, _ := unstructured.NestedString(cert.Object, "status", "notAfter")
	if !conditionTrue(cert, "Ready") || !found || err != nil || revision < 1 || notAfter == "" {
		return unavailable("CertificateNotReady", fmt.Errorf("Certificate %s is not Ready with a revision", c.Certificate))
	}
	request := object(requestGVK)
	// cert-manager names the request of a revision <certificate>-<revision>; its owner and annotation are checked too.
	requestName := c.Certificate + "-" + strconv.FormatInt(revision, 10)
	if err := reader.Get(ctx, client.ObjectKey{Namespace: o.CertManagerNamespace, Name: requestName}, request); err != nil {
		return readFailure("CertificateRequest", err)
	}
	owned := false
	for _, owner := range request.GetOwnerReferences() {
		owned = owned || owner.Kind == "Certificate" && owner.UID == cert.GetUID() && owner.Controller != nil && *owner.Controller
	}
	requestRef, _, _ := unstructured.NestedMap(request.Object, "spec", "issuerRef")
	if !owned || request.GetAnnotations()["cert-manager.io/certificate-revision"] != strconv.FormatInt(revision, 10) || !reflect.DeepEqual(requestRef, wantRef) {
		return refused("CertificateRequestMismatch", "CertificateRequest "+requestName+" is not the approved Certificate's request of its current revision")
	}
	if !conditionTrue(request, "Approved") || !conditionTrue(request, "Ready") {
		return unavailable("CertificateRequestNotReady", fmt.Errorf("CertificateRequest %s is not approved and issued", requestName))
	}
	encoded, _, _ := unstructured.NestedString(request.Object, "status", "certificate")
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return refused("CertificateRequestInvalid", "status.certificate is not base64")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return refused("CertificateRequestInvalid", "status.certificate is not one certificate")
	}
	if next, _ := pem.Decode(rest); next != nil {
		return refused("CertificateRequestInvalid", "status.certificate holds more than one certificate")
	}
	intermediatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}))
	issuer := object(clusterIssuerGV)
	if err := reader.Get(ctx, client.ObjectKey{Name: c.Certificate}, issuer); err != nil {
		return readFailure("ClusterIssuer", err)
	}
	spec, _, _ := unstructured.NestedMap(issuer.Object, "spec")
	if !reflect.DeepEqual(spec, map[string]any{"ca": map[string]any{"secretName": secret}}) {
		return refused("ClusterIssuerMismatch", "ClusterIssuer "+c.Certificate+" does not sign from the approved Certificate's Secret")
	}
	var spire corev1.ConfigMap
	if err := reader.Get(ctx, client.ObjectKey{Namespace: o.SPIRENamespace, Name: o.SPIREConfigMap}, &spire); err != nil {
		return readFailure("SPIREServerConfig", err)
	}
	conf := spire.Data["server.conf"]
	names := issuerName.FindAllStringSubmatch(conf, -1)
	if len(upstreamAuthority.FindAllString(conf, -1)) != 1 || len(names) != 1 || names[0][1] != c.Certificate {
		return refused("SPIREUpstreamMismatch", "SPIRE server.conf does not name exactly one cert-manager upstream "+c.Certificate)
	}
	derived, certNotAfter, err := trustprofile.SPIREIntermediateIssuer(c.Name, intermediatePEM, root, now)
	if err != nil {
		return refused("IntermediateInvalid", err.Error())
	}
	if trustprofile.Stamp(certNotAfter) != notAfter {
		return refused("CertificateRequestMismatch", "the issued certificate's notAfter differs from the Certificate status")
	}
	evidence := trustprofile.Evidence{Issuer: &derived, Message: fmt.Sprintf("revision %d, CertificateRequest %s", revision, request.GetUID())}
	policy := object(policyGVK)
	if err := reader.Get(ctx, client.ObjectKey{Name: c.SPIRECAPolicy}, policy); err == nil {
		value, _, _ := unstructured.NestedString(policy.Object, "spec", "constraints", "maxDuration")
		if d, err := time.ParseDuration(value); err == nil && d > 0 {
			evidence.SPIRECAMaxDuration = d
		}
	}
	if evidence.SPIRECAMaxDuration == 0 {
		evidence.Message += "; SPIRE CA maxDuration of " + c.SPIRECAPolicy + " unknown, so no retirement"
	}
	return evidence
}

// nodeView is one node and its report, as one pass read them.
type nodeView struct {
	name   string
	report *api.NodeTrustReport
	fresh  bool
}

type heartbeat struct {
	observedAt metav1.Time
	seenAt     time.Time
	changed    bool
}

// readNodes lists a cluster's nodes (metadata only) and its node reports, and marks each report fresh when this
// process saw its heartbeat change within the allowed age. The node agent's clock is never compared with this one,
// as Kubernetes' node lifecycle controller does with node Leases: after a restart a report counts again only once its
// heartbeat has moved.
func (r *IssuerApprovalReconciler) readNodes(ctx context.Context, cluster string, reader client.Reader, now time.Time) ([]nodeView, error) {
	nodes := &metav1.PartialObjectMetadataList{}
	nodes.SetGroupVersionKind(nodeGVK)
	if err := reader.List(ctx, nodes); err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}
	var reports api.NodeTrustReportList
	if err := reader.List(ctx, &reports); err != nil {
		return nil, fmt.Errorf("list node reports: %w", err)
	}
	byName := map[string]*api.NodeTrustReport{}
	for i := range reports.Items {
		byName[reports.Items[i].Name] = &reports.Items[i]
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.heartbeats == nil {
		r.heartbeats = map[string]heartbeat{}
	}
	views := make([]nodeView, 0, len(nodes.Items))
	listed := map[string]bool{}
	for _, n := range nodes.Items {
		view := nodeView{name: n.Name, report: byName[n.Name]}
		key := cluster + "/" + n.Name
		listed[key] = true
		if view.report != nil && view.report.Status.Cluster == cluster {
			h, seen := r.heartbeats[key]
			switch {
			case !seen:
				h = heartbeat{observedAt: view.report.Status.ObservedAt, seenAt: now}
			case !h.observedAt.Equal(&view.report.Status.ObservedAt):
				h = heartbeat{observedAt: view.report.Status.ObservedAt, seenAt: now, changed: true}
			}
			r.heartbeats[key] = h
			view.fresh = h.changed && now.Sub(h.seenAt) <= r.Options.ReportMaxAge
		}
		views = append(views, view)
	}
	// Forget the heartbeats of nodes that left the cluster, so the map stays bounded by the node count.
	for key := range r.heartbeats {
		if strings.HasPrefix(key, cluster+"/") && !listed[key] {
			delete(r.heartbeats, key)
		}
	}
	return views, nil
}

func summarize(cluster string, views []nodeView, accepting func(nodeView) bool) api.NodeSummary {
	s := api.NodeSummary{Cluster: cluster, Nodes: int32(len(views))}
	var missing, stale []string
	for _, v := range views {
		switch {
		case v.report == nil:
			missing = append(missing, v.name)
		case !v.fresh:
			stale = append(stale, v.name)
		default:
			s.Fresh++
			if accepting != nil && accepting(v) {
				s.Accepting++
			}
		}
	}
	if len(missing) > 0 {
		s.Message += fmt.Sprintf("no report: %v. ", missing)
	}
	if len(stale) > 0 {
		s.Message += fmt.Sprintf("stale report: %v. ", stale)
	}
	return s
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

// accepts: the node's pins file and ztunnel's loaded origin hold the approval's root, and ztunnel's checkpoint holds
// the cluster's live generation and digest as current (Cilium agent and ztunnel; see api.ZtunnelReport).
func accepts(v nodeView, t target) bool {
	if !t.live || !v.fresh || v.report == nil {
		return false
	}
	p, z := v.report.Status.Pins, v.report.Status.Ztunnel
	pinsOK := p.State == api.PinsUnchanged || p.State == api.PinsWritten || p.State == api.PinsReadOnly
	return pinsOK && contains(p.RootSHA256, t.root) && z.State == api.ZtunnelAccepted && z.AcceptedGeneration > 0 && uint64(z.AcceptedGeneration) == t.generation &&
		z.ApprovalDigest == t.digest && contains(z.LoadedRootSHA256, t.root)
}

// trusts: ztunnel on this node holds this issuer key for this trust domain in its current checkpoint.
func trusts(v nodeView, domain, spki string) bool {
	if !v.fresh || v.report == nil || v.report.Status.Ztunnel.State != api.ZtunnelAccepted {
		return false
	}
	for _, t := range v.report.Status.Ztunnel.TrustedIssuers {
		if t.TrustDomain == domain && t.SPKISHA256 == spki {
			return true
		}
	}
	return false
}
