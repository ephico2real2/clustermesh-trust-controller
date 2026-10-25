package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

const (
	clusterCASecret         = "cmtc-spire-cluster-ca"
	clusterCAApproval       = "cmtc-spire-cluster-ca-approval"
	clusterCANamespace      = "cert-manager"
	clusterCAOwner          = "security.cmtc.io/pki-owner"
	clusterCACluster        = "security.cmtc.io/pki-cluster"
	clusterCARole           = "security.cmtc.io/pki-role"
	clusterCACSR            = "security.cmtc.io/public-csr"
	clusterCARoot           = "security.cmtc.io/root-sha256"
	clusterCAOwnerValue     = "cmtc-lab-pki"
	clusterCAApprovalKey    = "approval.json"
	clusterCAMaxAttempts    = 5
	clusterCAMaxPublicBytes = 64 * 1024
)

type clusterCAOptions struct {
	Cluster     string
	SecretUID   types.UID
	RootSHA256  string
	ApprovalUID types.UID // required only for cluster-ca-complete
	Log         *slog.Logger
	Now         func() time.Time
}
type clusterCAPublic struct {
	SchemaVersion     int    `json:"schemaVersion"`
	Cluster           string `json:"cluster"`
	SecretNamespace   string `json:"secretNamespace"`
	SecretName        string `json:"secretName"`
	SecretUID         string `json:"secretUID"`
	ResourceVersion   string `json:"resourceVersion"`
	RootSHA256        string `json:"rootSHA256"`
	CSRSHA256         string `json:"csrSHA256"`
	ClusterIssuerCSR  string `json:"clusterIssuerCSR"`
	CertificateSHA256 string `json:"certificateSHA256,omitempty"`
	Status            string `json:"status"`
}
type clusterCASigningApproval struct {
	SchemaVersion         int    `json:"schemaVersion"`
	Cluster               string `json:"cluster"`
	SecretUID             string `json:"secretUID"`
	SecretResourceVersion string `json:"secretResourceVersion"`
	CSRSHA256             string `json:"csrSHA256"`
	RootSHA256            string `json:"rootSHA256"`
	CertificatePEM        string `json:"certificatePEM"`
}

func clusterCAHash(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func clusterCAPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
func clusterCAUID(s types.UID) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-') {
			return false
		}
	}
	return true
}
func (o clusterCAOptions) validate(complete bool) error {
	if o.Cluster != "cmtc-a" && o.Cluster != "cmtc-b" {
		return errors.New("cluster-ca mode supports only the existing cmtc-a/b labs")
	}
	if !clusterCAUID(o.SecretUID) || !clusterCAPin(o.RootSHA256) || complete && !clusterCAUID(o.ApprovalUID) {
		return errors.New("independent Secret UID, root SHA256 and completion approval UID required")
	}
	return nil
}
func (o clusterCAOptions) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}
func (o clusterCAOptions) logger() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.New(slog.DiscardHandler)
}
func clusterCASubject(cluster string) string { return cluster + " SPIRE cluster CA" }
func clusterCASubjectName(cluster string) pkix.Name {
	return pkix.Name{CommonName: clusterCASubject(cluster)}
}
func exactPEM(raw []byte, kind string, max int) (*pem.Block, error) {
	if len(raw) == 0 || len(raw) > max {
		return nil, errors.New("bounded PEM required")
	}
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != kind || len(b.Headers) != 0 || len(rest) != 0 || !bytes.Equal(raw, pem.EncodeToMemory(b)) {
		return nil, errors.New("one exact canonical PEM block required")
	}
	return b, nil
}
func validateClusterCSR(raw string, cluster string) (*x509.CertificateRequest, error) {
	b, e := exactPEM([]byte(raw), "CERTIFICATE REQUEST", 8192)
	if e != nil {
		return nil, e
	}
	csr, e := x509.ParseCertificateRequest(b.Bytes)
	if e != nil {
		return nil, e
	}
	if e = csr.CheckSignature(); e != nil {
		return nil, e
	}
	// x509.ParseCertificateRequest ignores some unknown attributes. Inspect
	// the signed raw request rather than trusting that lossy projection.
	var info struct {
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []asn1.RawValue `asn1:"tag:0"`
	}
	rest, e := asn1.Unmarshal(csr.RawTBSCertificateRequest, &info)
	subject, e2 := asn1.Marshal(clusterCASubjectName(cluster).ToRDNSequence())
	if e != nil || e2 != nil || len(rest) != 0 || info.Version != 0 || len(info.Attributes) != 0 || !bytes.Equal(csr.RawSubject, subject) || csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, errors.New("CSR contains unapproved signed attributes or encoding")
	}

	if !bytes.Equal(csr.Raw, b.Bytes) || csr.Subject.CommonName != clusterCASubject(cluster) || len(csr.Subject.Names) != 1 || csr.Subject.Names[0].Type.String() != "2.5.4.3" || len(csr.Extensions) != 0 || len(csr.ExtraExtensions) != 0 || len(csr.Attributes) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0 || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return nil, errors.New("CSR subject/extensions are outside exact cluster CA request")
	}
	public, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return nil, errors.New("cluster CA CSR must use P-256")
	}
	return csr, nil
}
func clusterCAKeyMatches(keyPEM []byte, csr *x509.CertificateRequest) error {
	b, e := exactPEM(keyPEM, "PRIVATE KEY", 16384)
	if e != nil {
		return e
	}
	key, e := x509.ParsePKCS8PrivateKey(b.Bytes)
	if e != nil {
		return e
	}
	k, ok := key.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return errors.New("cluster CA key must be P-256 PKCS8")
	}
	keyDER, e := x509.MarshalPKIXPublicKey(k.Public())
	if e != nil {
		return e
	}
	csrDER, e := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if e != nil {
		return e
	}
	if !bytes.Equal(keyDER, csrDER) {
		return errors.New("cluster CA key differs from stored public CSR")
	}
	return nil
}
func checkClusterCASecret(s *corev1.Secret, o clusterCAOptions) error {
	if s == nil || s.Namespace != clusterCANamespace || s.Name != clusterCASecret || s.UID != o.SecretUID || s.ResourceVersion == "" || s.DeletionTimestamp != nil || len(s.OwnerReferences) != 0 || s.Immutable != nil && *s.Immutable || s.Labels[clusterCAOwner] != clusterCAOwnerValue || s.Labels[clusterCACluster] != o.Cluster || s.Labels[clusterCARole] != "spire-cluster-ca" || s.Annotations[clusterCARoot] != o.RootSHA256 {
		return errors.New("Secret differs from pinned owned cluster CA")
	}
	if s.Type != corev1.SecretTypeOpaque && s.Type != corev1.SecretTypeTLS {
		return errors.New("unsupported cluster CA Secret type")
	}
	for k := range s.Data {
		if k != "tls.key" && k != "tls.crt" {
			return errors.New("unexpected cluster CA Secret data field")
		}
	}
	if len(s.Data) == 0 && s.Annotations[clusterCACSR] == "" && s.Type == corev1.SecretTypeOpaque {
		return nil
	}
	csr, e := validateClusterCSR(s.Annotations[clusterCACSR], o.Cluster)
	if e != nil {
		return e
	}
	if e = clusterCAKeyMatches(s.Data["tls.key"], csr); e != nil {
		return e
	}
	if s.Type == corev1.SecretTypeOpaque && (len(s.Data) != 1 && len(s.Data) != 2 || len(s.Data) == 2 && len(s.Data["tls.crt"]) == 0) {
		return errors.New("pending Secret has unexpected certificate state")
	}
	if s.Type == corev1.SecretTypeTLS && (len(s.Data) != 2 || len(s.Data["tls.crt"]) == 0) {
		return errors.New("completed TLS Secret has missing fields")
	}
	return nil
}
func parseClusterCAChain(raw string, csr *x509.CertificateRequest, o clusterCAOptions) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > clusterCAMaxPublicBytes {
		return nil, errors.New("bounded public CA chain required")
	}
	remaining := []byte(raw)
	certs := []*x509.Certificate{}
	canonical := []byte{}
	for len(remaining) > 0 {
		b, rest := pem.Decode(remaining)
		if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(certs) >= 2 {
			return nil, errors.New("exact parent/root certificate chain required")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, e
		}
		if !bytes.Equal(c.Raw, b.Bytes) {
			return nil, errors.New("trailing DER in CA certificate")
		}
		canonical = append(canonical, pem.EncodeToMemory(b)...)
		certs = append(certs, c)
		remaining = rest
	}
	if len(certs) != 2 || !bytes.Equal(canonical, []byte(raw)) {
		return nil, errors.New("canonical two-certificate cluster CA/root chain required")
	}
	parent, root := certs[0], certs[1]
	now := o.now()
	for _, c := range certs {
		if !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 || len(c.UnhandledCriticalExtensions) != 0 {
			return nil, errors.New("noncurrent or unsupported signing CA")
		}
		constraints := false
		for _, ext := range c.Extensions {
			switch ext.Id.String() {
			case "2.5.29.19":
				constraints = ext.Critical
			case "2.5.29.15", "2.5.29.14", "2.5.29.35":
			default:
				return nil, errors.New("CA extension outside bounded approval profile")
			}
		}
		if !constraints {
			return nil, errors.New("critical CA basic constraints required")
		}
	}
	if clusterCAHash(root.Raw) != o.RootSHA256 || !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil || root.MaxPathLenZero || root.MaxPathLen >= 0 && root.MaxPathLen < 2 {
		return nil, errors.New("root pin/signature/pathLen2 approval rejected")
	}
	if parent.MaxPathLen != 1 || parent.MaxPathLenZero || parent.Subject.CommonName != clusterCASubject(o.Cluster) || len(parent.Subject.Names) != 1 || !bytes.Equal(parent.RawSubject, csr.RawSubject) || !bytes.Equal(parent.RawIssuer, root.RawSubject) || parent.CheckSignatureFrom(root) != nil || parent.NotBefore.Before(root.NotBefore) || parent.NotAfter.After(root.NotAfter) || parent.NotAfter.Sub(parent.NotBefore) > 825*24*time.Hour {
		return nil, errors.New("cluster parent identity/pathLen1/lifetime/lineage rejected")
	}
	key, e := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if e != nil {
		return nil, e
	}
	if bytes.Equal(parent.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) {
		return nil, errors.New("cluster parent must not reuse the organizational root key")
	}
	if !bytes.Equal(parent.RawSubjectPublicKeyInfo, key) {
		return nil, errors.New("signed parent key differs from approved CSR")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, e := parent.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if e != nil || len(chains) != 1 || len(chains[0]) != 2 {
		return nil, errors.New("cluster parent does not have one approved direct root lineage")
	}
	return parent, nil
}
func readClusterCAApproval(ctx context.Context, k kubernetes.Interface, o clusterCAOptions) (clusterCASigningApproval, *corev1.ConfigMap, error) {
	var a clusterCASigningApproval
	cm, e := k.CoreV1().ConfigMaps(clusterCANamespace).Get(ctx, clusterCAApproval, metav1.GetOptions{})
	if e != nil {
		return a, nil, e
	}
	if cm.UID != o.ApprovalUID || cm.ResourceVersion == "" || cm.DeletionTimestamp != nil || len(cm.OwnerReferences) != 0 || cm.Immutable == nil || !*cm.Immutable || len(cm.Data) != 1 || len(cm.BinaryData) != 0 || cm.Labels[clusterCAOwner] != clusterCAOwnerValue || cm.Labels[clusterCACluster] != o.Cluster || cm.Labels[clusterCARole] != "spire-cluster-ca-approval" {
		return a, nil, errors.New("approval ConfigMap differs from pinned immutable owner")
	}
	raw := cm.Data[clusterCAApprovalKey]
	if len(raw) == 0 || len(raw) > clusterCAMaxPublicBytes {
		return a, nil, errors.New("bounded public approval required")
	}
	// Token scan rejects duplicates before decoding typed fields.
	d := json.NewDecoder(bytes.NewBufferString(raw))
	token, e := d.Token()
	if e != nil || token != json.Delim('{') {
		return a, nil, errors.New("approval object required")
	}
	seen := map[string]bool{}
	allowed := map[string]bool{"schemaVersion": true, "cluster": true, "secretUID": true, "secretResourceVersion": true, "csrSHA256": true, "rootSHA256": true, "certificatePEM": true}
	for d.More() {
		token, e = d.Token()
		if e != nil {
			return a, nil, e
		}
		name, ok := token.(string)
		if !ok || !allowed[name] || seen[name] {
			return a, nil, errors.New("unknown/duplicate public approval field")
		}
		seen[name] = true
		var v json.RawMessage
		if e = d.Decode(&v); e != nil {
			return a, nil, e
		}
	}
	if token, e = d.Token(); e != nil || token != json.Delim('}') {
		return a, nil, errors.New("malformed public approval")
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return a, nil, errors.New("one public approval required")
	}
	if e = json.Unmarshal([]byte(raw), &a); e != nil {
		return a, nil, e
	}
	if a.SchemaVersion != 1 || a.Cluster != o.Cluster || a.SecretUID != string(o.SecretUID) || a.SecretResourceVersion == "" || a.RootSHA256 != o.RootSHA256 || !clusterCAPin(a.CSRSHA256) {
		return a, nil, errors.New("approval public identity/pins differ")
	}
	return a, cm, nil
}
func clusterCAResult(s *corev1.Secret, o clusterCAOptions) (clusterCAPublic, error) {
	result := clusterCAPublic{SchemaVersion: 1, Cluster: o.Cluster, SecretNamespace: clusterCANamespace, SecretName: clusterCASecret, SecretUID: string(s.UID), ResourceVersion: s.ResourceVersion, RootSHA256: o.RootSHA256, Status: "pending", ClusterIssuerCSR: s.Annotations[clusterCACSR]}
	csr, e := validateClusterCSR(result.ClusterIssuerCSR, o.Cluster)
	if e != nil {
		return result, e
	}
	result.CSRSHA256 = clusterCAHash(csr.Raw)
	if len(s.Data["tls.crt"]) != 0 {
		c, e := parseClusterCAChain(string(s.Data["tls.crt"]), csr, o)
		if e != nil {
			return result, e
		}
		result.CertificateSHA256 = clusterCAHash(c.Raw)
		result.Status = "ready"
	}
	return result, nil
}
func clusterCAReadRetry(err error) bool {
	return apierrors.IsConflict(err) || apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) || apierrors.IsServiceUnavailable(err) || apierrors.IsTooManyRequests(err) || apierrors.IsInternalError(err)
}
func runClusterCA(ctx context.Context, k kubernetes.Interface, o clusterCAOptions, complete bool, out io.Writer) error {
	if e := o.validate(complete); e != nil {
		return e
	}
	if k == nil || out == nil {
		return errors.New("explicit Kubernetes client/output required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	started := time.Now()
	log := o.logger().With("component", "lab-cluster-ca", "cluster", o.Cluster, "secret", clusterCANamespace+"/"+clusterCASecret, "secretUID", o.SecretUID)
	if deadline, ok := ctx.Deadline(); ok {
		log = log.With("deadline", deadline.UTC())
	}
	var proposedKey []byte
	var proposedCSR string
	var last error
	for attempt := 1; attempt <= clusterCAMaxAttempts; attempt++ {
		stage := "read-secret"
		retry := false
		expectedCertificate := ""
		result, e := func() (clusterCAPublic, error) {
			if e := ctx.Err(); e != nil {
				return clusterCAPublic{}, e
			}
			secret, e := k.CoreV1().Secrets(clusterCANamespace).Get(ctx, clusterCASecret, metav1.GetOptions{})
			if e != nil {
				retry = clusterCAReadRetry(e)
				return clusterCAPublic{}, e
			}
			if e = checkClusterCASecret(secret, o); e != nil {
				return clusterCAPublic{}, e
			}
			if !complete {
				if secret.Annotations[clusterCACSR] == "" {
					stage = "initialize-key-csr"
					if proposedCSR == "" {
						proposedKey, proposedCSR, e = keyAndRequest(&x509.CertificateRequest{Subject: clusterCASubjectName(o.Cluster)})
						if e != nil {
							return clusterCAPublic{}, e
						}
					}
					desired := secret.DeepCopy()
					desired.Data = map[string][]byte{"tls.key": proposedKey}
					if desired.Annotations == nil {
						desired.Annotations = map[string]string{}
					}
					desired.Annotations[clusterCACSR] = proposedCSR
					if _, e = k.CoreV1().Secrets(clusterCANamespace).Update(ctx, desired, metav1.UpdateOptions{}); e != nil {
						retry = !apierrors.IsInvalid(e) && !apierrors.IsForbidden(e) && !apierrors.IsUnauthorized(e)
						return clusterCAPublic{}, e
					}
				}
			} else {
				stage = "read-public-approval"
				approval, cm, e := readClusterCAApproval(ctx, k, o)
				if e != nil {
					retry = clusterCAReadRetry(e)
					return clusterCAPublic{}, e
				}
				csr, e := validateClusterCSR(secret.Annotations[clusterCACSR], o.Cluster)
				if e != nil {
					return clusterCAPublic{}, e
				}
				if clusterCAHash(csr.Raw) != approval.CSRSHA256 {
					return clusterCAPublic{}, errors.New("approval CSR digest differs from stored key request")
				}
				stage = "verify-public-certificate"
				if _, e = parseClusterCAChain(approval.CertificatePEM, csr, o); e != nil {
					return clusterCAPublic{}, e
				}
				expectedCertificate = approval.CertificatePEM
				latest, e := k.CoreV1().ConfigMaps(clusterCANamespace).Get(ctx, clusterCAApproval, metav1.GetOptions{})
				if e != nil {
					retry = clusterCAReadRetry(e)
					return clusterCAPublic{}, e
				}
				if latest.UID != cm.UID || latest.ResourceVersion != cm.ResourceVersion || latest.DeletionTimestamp != nil {
					return clusterCAPublic{}, errors.New("approval changed during observation")
				}
				if len(secret.Data["tls.crt"]) != 0 {
					if !bytes.Equal(secret.Data["tls.crt"], []byte(approval.CertificatePEM)) {
						return clusterCAPublic{}, errors.New("existing completed certificate differs; explicit rotation required")
					}
				}
				if len(secret.Data["tls.crt"]) == 0 {
					if secret.ResourceVersion != approval.SecretResourceVersion {
						return clusterCAPublic{}, errors.New("pending Secret resourceVersion differs from public approval")
					}
					desired := secret.DeepCopy()
					desired.Data["tls.crt"] = []byte(approval.CertificatePEM)
					stage = "complete-certificate"
					if e = ctx.Err(); e != nil {
						return clusterCAPublic{}, e
					}
					if _, e = k.CoreV1().Secrets(clusterCANamespace).Update(ctx, desired, metav1.UpdateOptions{}); e != nil {
						retry = !apierrors.IsInvalid(e) && !apierrors.IsForbidden(e) && !apierrors.IsUnauthorized(e)
						return clusterCAPublic{}, e
					}
				}
			}
			stage = "confirm"
			confirmed, e := k.CoreV1().Secrets(clusterCANamespace).Get(ctx, clusterCASecret, metav1.GetOptions{})
			if e != nil {
				retry = clusterCAReadRetry(e)
				return clusterCAPublic{}, e
			}
			if e = checkClusterCASecret(confirmed, o); e != nil {
				return clusterCAPublic{}, e
			}
			if complete && (len(confirmed.Data["tls.crt"]) == 0 || !bytes.Equal(confirmed.Data["tls.crt"], []byte(expectedCertificate))) {
				return clusterCAPublic{}, errors.New("completion was not confirmed on the exact certificate")
			}
			return clusterCAResult(confirmed, o)
		}()
		if e == nil {
			if err := ctx.Err(); err != nil {
				return err
			}
			log.Info("Cluster CA state acknowledged; workload protection unverified", "stage", stage, "attempt", attempt, "elapsed", time.Since(started), "status", result.Status, "resourceVersion", result.ResourceVersion, "csrSHA256", result.CSRSHA256)
			return json.NewEncoder(out).Encode(result)
		}
		last = e
		backoff := time.Duration(1<<uint(attempt-1)) * 50 * time.Millisecond
		log.Error("Cluster CA operation failed", "stage", stage, "attempt", attempt, "elapsed", time.Since(started), "backoff", backoff, "error", e)
		if !retry || attempt == clusterCAMaxAttempts {
			return fmt.Errorf("cluster CA %s failed: %w", stage, e)
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}
