package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

type clusterCAFixture struct {
	client  *fake.Clientset
	options clusterCAOptions
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	now     time.Time
}

func newClusterCAFixture(t *testing.T) *clusterCAFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture organizational root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(900 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 2, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	o := clusterCAOptions{Cluster: "cmtc-a", SecretUID: "secret-test-uid", RootSHA256: clusterCAHash(root.Raw), Now: func() time.Time { return now }}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: clusterCASecret, Namespace: clusterCANamespace, UID: o.SecretUID, ResourceVersion: "10", Labels: map[string]string{clusterCAOwner: clusterCAOwnerValue, clusterCACluster: o.Cluster, clusterCARole: "spire-cluster-ca"}, Annotations: map[string]string{clusterCARoot: o.RootSHA256}}, Type: corev1.SecretTypeOpaque}
	client := fake.NewClientset(secret)
	// Model real UID/RV compare-and-swap; client-go's default tracker does not.
	client.PrependReactor("update", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		desired := action.(ktesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		gvr := corev1.SchemeGroupVersion.WithResource("secrets")
		old, e := client.Tracker().Get(gvr, desired.Namespace, desired.Name)
		if e != nil {
			return true, nil, e
		}
		current := old.(*corev1.Secret)
		if desired.UID != current.UID || desired.ResourceVersion != current.ResourceVersion {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, desired.Name, errors.New("UID/RV mismatch"))
		}
		version, e := strconv.Atoi(current.ResourceVersion)
		if e != nil {
			return true, nil, e
		}
		desired.ResourceVersion = strconv.Itoa(version + 1)
		if e = client.Tracker().Update(gvr, desired, desired.Namespace); e != nil {
			return true, nil, e
		}
		return true, desired.DeepCopy(), nil
	})
	return &clusterCAFixture{client: client, options: o, root: root, rootKey: key, now: now}
}
func (f *clusterCAFixture) secret(t *testing.T) *corev1.Secret {
	t.Helper()
	s, e := f.client.CoreV1().Secrets(clusterCANamespace).Get(t.Context(), clusterCASecret, metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func (f *clusterCAFixture) init(t *testing.T) clusterCAPublic {
	t.Helper()
	var out bytes.Buffer
	if e := runClusterCA(t.Context(), f.client, f.options, false, &out); e != nil {
		t.Fatal(e)
	}
	var p clusterCAPublic
	if e := json.Unmarshal(out.Bytes(), &p); e != nil {
		t.Fatal(e)
	}
	return p
}
func (f *clusterCAFixture) approval(t *testing.T, edit func(*x509.Certificate), editApproval func(*clusterCASigningApproval)) (*corev1.ConfigMap, clusterCASigningApproval) {
	t.Helper()
	s := f.secret(t)
	csr, e := validateClusterCSR(s.Annotations[clusterCACSR], f.options.Cluster)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: csr.Subject, NotBefore: f.now.Add(-5 * time.Minute), NotAfter: f.now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if edit != nil {
		edit(cert)
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, f.root, csr.PublicKey, f.rootKey)
	if e != nil {
		t.Fatal(e)
	}
	chain := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.root.Raw}))
	a := clusterCASigningApproval{SchemaVersion: 1, Cluster: f.options.Cluster, SecretUID: string(s.UID), SecretResourceVersion: s.ResourceVersion, CSRSHA256: clusterCAHash(csr.Raw), RootSHA256: f.options.RootSHA256, CertificatePEM: chain}
	if editApproval != nil {
		editApproval(&a)
	}
	raw, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	immutable := true
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: clusterCAApproval, Namespace: clusterCANamespace, UID: "approval-test-uid", ResourceVersion: "20", Labels: map[string]string{clusterCAOwner: clusterCAOwnerValue, clusterCACluster: f.options.Cluster, clusterCARole: "spire-cluster-ca-approval"}}, Immutable: &immutable, Data: map[string]string{clusterCAApprovalKey: string(raw)}}
	if _, e = f.client.CoreV1().ConfigMaps(clusterCANamespace).Create(t.Context(), cm, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	f.options.ApprovalUID = cm.UID
	return cm, a
}
func differentClusterCAHash(s string) string {
	if s[0] == '0' {
		return "1" + s[1:]
	}
	return "0" + s[1:]
}
func countClusterCAUpdates(c *fake.Clientset) int {
	n := 0
	for _, a := range c.Actions() {
		if a.GetVerb() == "update" && a.GetResource().Resource == "secrets" {
			n++
		}
	}
	return n
}
func TestClusterCAInitializesPrecreatedOpaqueSecretAndRetriesSameCSR(t *testing.T) {
	f := newClusterCAFixture(t)
	first := f.init(t)
	key := bytes.Clone(f.secret(t).Data["tls.key"])
	second := f.init(t)
	if first.ClusterIssuerCSR != second.ClusterIssuerCSR || first.CSRSHA256 != second.CSRSHA256 || first.ResourceVersion != second.ResourceVersion || countClusterCAUpdates(f.client) != 1 || !bytes.Equal(key, f.secret(t).Data["tls.key"]) {
		t.Fatal("retry changed initialized key/CSR or resourceVersion")
	}
	if first.Status != "pending" || first.SecretUID != string(f.options.SecretUID) {
		t.Fatal("wrong public pending state")
	}
	raw, _ := json.Marshal(second)
	for _, marker := range [][]byte{key, []byte("PRIVATE KEY"), []byte("tls.key"), []byte("adsServerCSR")} {
		if bytes.Contains(raw, marker) {
			t.Fatal("private/legacy data in public output")
		}
	}
	for _, a := range f.client.Actions() {
		if a.GetVerb() == "create" && a.GetResource().Resource == "secrets" {
			t.Fatal("initializer requires broad create authority")
		}
	}
}
func TestClusterCACompletionIsPublicApprovedUIDBoundAndIdempotent(t *testing.T) {
	f := newClusterCAFixture(t)
	p := f.init(t)
	key := bytes.Clone(f.secret(t).Data["tls.key"])
	_, approval := f.approval(t, nil, nil)
	var out bytes.Buffer
	if e := runClusterCA(t.Context(), f.client, f.options, true, &out); e != nil {
		t.Fatal(e)
	}
	var result clusterCAPublic
	if e := json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	s := f.secret(t)
	if result.Status != "ready" || result.CSRSHA256 != p.CSRSHA256 || s.Type != corev1.SecretTypeTLS || len(s.Data) != 2 || string(s.Data["tls.crt"]) != approval.CertificatePEM || !bytes.Equal(s.Data["tls.key"], key) {
		t.Fatal("completion changed key or failed public chain contract")
	}
	updates := countClusterCAUpdates(f.client)
	out.Reset()
	if e := runClusterCA(t.Context(), f.client, f.options, true, &out); e != nil {
		t.Fatal(e)
	}
	if countClusterCAUpdates(f.client) != updates {
		t.Fatal("idempotent completion churned Secret")
	}
}
func TestClusterCALostInitializationACKConfirmsStoredKeyWithoutMintingAgain(t *testing.T) {
	f := newClusterCAFixture(t)
	lost := &atomic.Bool{}
	var storedCSR string
	f.client.PrependReactor("update", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !lost.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		s := action.(ktesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		s.ResourceVersion = "11"
		storedCSR = s.Annotations[clusterCACSR]
		if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
			return true, nil, e
		}
		return true, nil, apierrors.NewTimeoutError("injected lost write acknowledgment", 0)
	})
	result := f.init(t)
	if result.ClusterIssuerCSR != storedCSR || countClusterCAUpdates(f.client) != 1 {
		t.Fatal("lost ACK regenerated request or repeated committed update")
	}
}
func TestClusterCAConflictsAndConcurrentInitializersConvergeOnOneStoredRequest(t *testing.T) {
	f := newClusterCAFixture(t)
	var wg sync.WaitGroup
	results := make(chan string, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var out bytes.Buffer
			e := runClusterCA(context.Background(), f.client, f.options, false, &out)
			if e != nil {
				errs <- e
				return
			}
			var p clusterCAPublic
			e = json.Unmarshal(out.Bytes(), &p)
			if e != nil {
				errs <- e
				return
			}
			results <- p.ClusterIssuerCSR
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
	a, b := <-results, <-results
	if a == "" || a != b {
		t.Fatal("concurrent retries emitted different requests")
	}
}
func TestClusterCALostCompletionACKRecoversWithoutReplacingKey(t *testing.T) {
	f := newClusterCAFixture(t)
	f.init(t)
	f.approval(t, nil, nil)
	lost := &atomic.Bool{}
	f.client.PrependReactor("update", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		s := action.(ktesting.UpdateAction).GetObject().(*corev1.Secret)
		if s.Type != corev1.SecretTypeTLS || !lost.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		s = s.DeepCopy()
		s.ResourceVersion = "12"
		if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
			return true, nil, e
		}
		return true, nil, apierrors.NewTimeoutError("injected lost completion ACK", 0)
	})
	var out bytes.Buffer
	if e := runClusterCA(t.Context(), f.client, f.options, true, &out); e != nil {
		t.Fatal(e)
	}
	if !lost.Load() || f.secret(t).Type != corev1.SecretTypeTLS {
		t.Fatal("lost completion was not recovered")
	}
}
func TestClusterCARejectsForeignUIDOwnershipPartialStateAndWrongRootBeforeWrite(t *testing.T) {
	for _, kind := range []string{"uid", "owner", "cluster", "role", "root", "partial-key", "extra-data"} {
		t.Run(kind, func(t *testing.T) {
			f := newClusterCAFixture(t)
			s := f.secret(t)
			switch kind {
			case "uid":
				s.UID = "replacement-uid"
			case "owner":
				s.Labels[clusterCAOwner] = "foreign"
			case "cluster":
				s.Labels[clusterCACluster] = "cmtc-b"
			case "role":
				s.Labels[clusterCARole] = "foreign"
			case "root":
				s.Annotations[clusterCARoot] = differentClusterCAHash(f.options.RootSHA256)
			case "partial-key":
				s.Data = map[string][]byte{"tls.key": []byte("partial")}
			case "extra-data":
				s.Data = map[string][]byte{"other": []byte("foreign")}
			}
			if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
				t.Fatal(e)
			}
			var out bytes.Buffer
			if runClusterCA(t.Context(), f.client, f.options, false, &out) == nil || out.Len() != 0 || countClusterCAUpdates(f.client) != 0 {
				t.Fatal("foreign/partial state was mutated or published")
			}
		})
	}
}
func TestClusterCARejectsWrongCSRKeySubjectExtraSANAndTrailingPEM(t *testing.T) {
	for _, kind := range []string{"key", "subject", "san", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			f := newClusterCAFixture(t)
			f.init(t)
			s := f.secret(t)
			switch kind {
			case "key":
				key, _, e := keyAndRequest(&x509.CertificateRequest{Subject: clusterCASubjectName(f.options.Cluster)})
				if e != nil {
					t.Fatal(e)
				}
				s.Data["tls.key"] = key
			case "subject":
				_, csr, e := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: "other"}})
				if e != nil {
					t.Fatal(e)
				}
				s.Annotations[clusterCACSR] = csr
			case "san":
				_, csr, e := keyAndRequest(&x509.CertificateRequest{Subject: clusterCASubjectName(f.options.Cluster), DNSNames: []string{"forbidden.example"}})
				if e != nil {
					t.Fatal(e)
				}
				s.Annotations[clusterCACSR] = csr
			case "trailing":
				s.Annotations[clusterCACSR] += "garbage"
			}
			if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
				t.Fatal(e)
			}
			before := countClusterCAUpdates(f.client)
			var out bytes.Buffer
			if runClusterCA(t.Context(), f.client, f.options, false, &out) == nil || out.Len() != 0 || countClusterCAUpdates(f.client) != before {
				t.Fatal("malformed request/key was accepted")
			}
		})
	}
}
func TestClusterCACompletionRejectsUnapprovedOrMalformedPublicCertificate(t *testing.T) {
	for _, kind := range []string{"expired", "future", "pathlen", "subject", "not-ca", "unknown-extension", "root", "csr", "uid", "rv", "trailing", "unknown-json", "duplicate-json", "wrong-root-certificate", "bad-signature"} {
		t.Run(kind, func(t *testing.T) {
			f := newClusterCAFixture(t)
			f.init(t)
			edit := func(c *x509.Certificate) {
				switch kind {
				case "expired":
					c.NotBefore = f.now.Add(-2 * time.Hour)
					c.NotAfter = f.now.Add(-time.Hour)
				case "future":
					c.NotBefore = f.now.Add(time.Hour)
				case "pathlen":
					c.MaxPathLen = 0
					c.MaxPathLenZero = true
				case "subject":
					c.Subject.CommonName = "foreign"
				case "not-ca":
					c.IsCA = false
					c.KeyUsage = x509.KeyUsageDigitalSignature
					c.MaxPathLen = 0
					c.MaxPathLenZero = false
				case "unknown-extension":
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				}
			}
			cm, _ := f.approval(t, edit, func(a *clusterCASigningApproval) {
				switch kind {
				case "root":
					a.RootSHA256 = differentClusterCAHash(a.RootSHA256)
				case "csr":
					a.CSRSHA256 = differentClusterCAHash(a.CSRSHA256)
				case "uid":
					a.SecretUID = "other-uid"
				case "rv":
					a.SecretResourceVersion = "0"
				case "trailing":
					a.CertificatePEM += "garbage"
				case "wrong-root-certificate":
					b, _ := pem.Decode([]byte(a.CertificatePEM))
					other := newClusterCAFixture(t)
					a.CertificatePEM = string(pem.EncodeToMemory(b)) + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.root.Raw}))
				case "bad-signature":
					b, rest := pem.Decode([]byte(a.CertificatePEM))
					b.Bytes[len(b.Bytes)-1] ^= 1
					a.CertificatePEM = string(pem.EncodeToMemory(b)) + string(rest)
				}
			})
			if kind == "unknown-json" || kind == "duplicate-json" {
				raw := cm.Data[clusterCAApprovalKey]
				if kind == "unknown-json" {
					raw = raw[:len(raw)-1] + `,"unknown":true}`
				} else {
					raw = raw[:len(raw)-1] + `,"cluster":"cmtc-a"}`
				}
				cm.Data[clusterCAApprovalKey] = raw
				if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("configmaps"), cm, cm.Namespace); e != nil {
					t.Fatal(e)
				}
			}
			before := countClusterCAUpdates(f.client)
			var out bytes.Buffer
			if runClusterCA(t.Context(), f.client, f.options, true, &out) == nil || out.Len() != 0 || countClusterCAUpdates(f.client) != before {
				t.Fatal("bad public approval was applied")
			}
		})
	}
}
func TestClusterCAUIDReplacementDuringRetryNeverAdoptsReplacement(t *testing.T) {
	f := newClusterCAFixture(t)
	replace := &atomic.Bool{}
	f.client.PrependReactor("update", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		if !replace.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: clusterCANamespace, Name: clusterCASecret, UID: "replacement-uid", ResourceVersion: "99"}, Type: corev1.SecretTypeOpaque}
		if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
			return true, nil, e
		}
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "secrets"}, clusterCASecret, errors.New("replacement"))
	})
	var out bytes.Buffer
	if runClusterCA(t.Context(), f.client, f.options, false, &out) == nil || out.Len() != 0 {
		t.Fatal("replacement accepted")
	}
	s := f.secret(t)
	if s.UID != "replacement-uid" || len(s.Data) != 0 {
		t.Fatal("replacement was changed")
	}
}
func TestClusterCABoundedRetryLogsAndCancellation(t *testing.T) {
	f := newClusterCAFixture(t)
	var logs bytes.Buffer
	f.options.Log = slog.New(slog.NewJSONHandler(&logs, nil))
	f.client.PrependReactor("get", "secrets", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServiceUnavailable("injected API unavailable")
	})
	var out bytes.Buffer
	if runClusterCA(t.Context(), f.client, f.options, false, &out) == nil || out.Len() != 0 {
		t.Fatal("API failure was accepted")
	}
	for _, key := range []string{`"stage"`, `"attempt":5`, `"elapsed"`, `"deadline"`, `"backoff"`, `"error"`} {
		if !bytes.Contains(logs.Bytes(), []byte(key)) {
			t.Fatalf("missing structured retry field %s", key)
		}
	}
	f = newClusterCAFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if e := runClusterCA(ctx, f.client, f.options, false, &out); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if len(f.client.Actions()) != 0 {
		t.Fatal("canceled operation reached API")
	}
}
func TestClusterCAModeAndExplicitPinsRejectBeforeAPI(t *testing.T) {
	for _, kind := range []string{"cluster", "uid", "root", "approval"} {
		t.Run(kind, func(t *testing.T) {
			f := newClusterCAFixture(t)
			switch kind {
			case "cluster":
				f.options.Cluster = "cmtc-mtls"
			case "uid":
				f.options.SecretUID = ""
			case "root":
				f.options.RootSHA256 = "bad"
			case "approval":
				f.options.ApprovalUID = ""
			}
			var out bytes.Buffer
			if runClusterCA(t.Context(), f.client, f.options, true, &out) == nil || len(f.client.Actions()) != 0 {
				t.Fatal("invalid configuration reached API")
			}
		})
	}
	for _, mode := range []string{"", "legacy", "cluster-ca-init", "cluster-ca-complete"} {
		if _, e := selectMode(mode); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := selectMode("force"); e == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestClusterCAApprovalUIDAndConcurrentResourceVersionChangesAreRejected(t *testing.T) {
	for _, kind := range []string{"uid", "concurrent-rv"} {
		t.Run(kind, func(t *testing.T) {
			f := newClusterCAFixture(t)
			f.init(t)
			f.approval(t, nil, nil)
			if kind == "uid" {
				f.options.ApprovalUID = "foreign-approval-uid"
			} else {
				var gets atomic.Int32
				f.client.PrependReactor("get", "configmaps", func(action ktesting.Action) (bool, runtime.Object, error) {
					if gets.Add(1) != 2 {
						return false, nil, nil
					}
					gvr := corev1.SchemeGroupVersion.WithResource("configmaps")
					raw, e := f.client.Tracker().Get(gvr, clusterCANamespace, clusterCAApproval)
					if e != nil {
						return true, nil, e
					}
					cm := raw.(*corev1.ConfigMap).DeepCopy()
					cm.ResourceVersion = "21"
					if e = f.client.Tracker().Update(gvr, cm, cm.Namespace); e != nil {
						return true, nil, e
					}
					return true, cm, nil
				})
			}
			before := countClusterCAUpdates(f.client)
			var out bytes.Buffer
			if runClusterCA(t.Context(), f.client, f.options, true, &out) == nil || out.Len() != 0 || countClusterCAUpdates(f.client) != before {
				t.Fatal("replaced or changing public approval was applied")
			}
		})
	}
}
func TestClusterCACancellationAfterCommittedWritePublishesNothingAndLaterRetryReusesCSR(t *testing.T) {
	f := newClusterCAFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	var savedCSR string
	var once atomic.Bool
	f.client.PrependReactor("update", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if !once.CompareAndSwap(false, true) {
			return false, nil, nil
		}
		s := action.(ktesting.UpdateAction).GetObject().(*corev1.Secret).DeepCopy()
		s.ResourceVersion = "11"
		savedCSR = s.Annotations[clusterCACSR]
		if e := f.client.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, s.Namespace); e != nil {
			return true, nil, e
		}
		cancel()
		return true, nil, context.Canceled
	})
	var out bytes.Buffer
	if e := runClusterCA(ctx, f.client, f.options, false, &out); !errors.Is(e, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled write produced public acknowledgment", e)
	}
	retry := f.init(t)
	if retry.ClusterIssuerCSR != savedCSR || countClusterCAUpdates(f.client) != 1 {
		t.Fatal("cancellation recovery replaced committed key/CSR")
	}
}

func TestClusterCACancelledSuccessfulConfirmationDoesNotAcknowledge(t *testing.T) {
	f := newClusterCAFixture(t)
	first := f.init(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var reads atomic.Int32
	f.client.PrependReactor("get", "secrets", func(action ktesting.Action) (bool, runtime.Object, error) {
		if reads.Add(1) != 2 {
			return false, nil, nil
		}
		obj, err := f.client.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), clusterCANamespace, clusterCASecret)
		if err != nil {
			return true, nil, err
		}
		cancel()
		return true, obj, nil
	})
	var out bytes.Buffer
	err := runClusterCA(ctx, f.client, f.options, false, &out)
	if !errors.Is(err, context.Canceled) || out.Len() != 0 {
		t.Fatal("canceled confirmation acknowledged success", err, out.String())
	}
	next := f.init(t)
	if first.ClusterIssuerCSR != next.ClusterIssuerCSR || first.CSRSHA256 != next.CSRSHA256 || countClusterCAUpdates(f.client) != 1 {
		t.Fatal("confirmation cancellation changed persisted key/CSR")
	}
}
