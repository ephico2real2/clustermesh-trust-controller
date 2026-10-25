package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	"github.com/go-logr/zapr"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type profileFaultClient struct {
	client.Client
	updates    int
	getHook    func(context.Context, client.ObjectKey, client.Object) error
	updateHook func(context.Context, client.Object) error
}

func (c *profileFaultClient) Get(ctx context.Context, key client.ObjectKey, o client.Object, opts ...client.GetOption) error {
	if c.getHook != nil {
		if err := c.getHook(ctx, key, o); err != nil {
			return err
		}
	}
	return c.Client.Get(ctx, key, o, opts...)
}
func (c *profileFaultClient) Update(ctx context.Context, o client.Object, opts ...client.UpdateOption) error {
	c.updates++
	if c.updateHook != nil {
		return c.updateHook(ctx, o)
	}
	return c.Client.Update(ctx, o, opts...)
}
func producerApproval(t *testing.T, now time.Time) trustprofile.Approval {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public fixture root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(der []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	a := trustprofile.Approval{SchemaVersion: 1, Generation: 1, ExpiresAt: trustprofile.Stamp(now.Add(time.Hour)), Roots: []trustprofile.Root{{CertificatePEM: encode(der), SHA256: trustprofile.SHA(der)}}}
	for i, id := range []string{"cmtc-a", "cmtc-b"} {
		ik, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		it := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: id}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
		raw, e := x509.CreateCertificate(rand.Reader, it, root, &ik.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		ic, e := x509.ParseCertificate(raw)
		if e != nil {
			t.Fatal(e)
		}
		a.Clusters = append(a.Clusters, trustprofile.Cluster{ClusterID: id, TrustDomain: id + ".mesh", Issuers: []trustprofile.Issuer{{CertificatePEM: encode(raw), SPKISHA256: trustprofile.SHA(ic.RawSubjectPublicKeyInfo), RootSHA256: a.Roots[0].SHA256}}})
	}
	return a
}
func sourceObject(t *testing.T, a trustprofile.Approval, uid types.UID) *corev1.ConfigMap {
	t.Helper()
	raw, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	immutable := true
	return &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "approval", Namespace: "cmtc-system", UID: uid}, Immutable: &immutable, Data: map[string]string{trustprofile.ApprovalKey: string(raw)}}
}
func producerFixture(t *testing.T) (*IssuerProfileReconciler, *profileFaultClient, *corev1.ConfigMap, *corev1.ConfigMap, *time.Time, *prometheus.Registry) {
	t.Helper()
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	a := producerApproval(t, now)
	source := sourceObject(t, a, "source-v1")
	output := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "publication", Namespace: "cmtc-system", UID: "output-v1", Labels: map[string]string{trustprofile.OutputLabel: "true"}}}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := &profileFaultClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(source, output).Build()}
	reg := prometheus.NewRegistry()
	metrics, err := trustprofile.NewMetrics(reg, "cmtc-a")
	if err != nil {
		t.Fatal(err)
	}
	r := &IssuerProfileReconciler{Client: c, Reader: c, Options: IssuerProfileOptions{Source: client.ObjectKeyFromObject(source), Output: client.ObjectKeyFromObject(output), SourceUID: source.UID, OutputUID: output.UID, MinimumGeneration: 1, RootPins: []string{a.Roots[0].SHA256}, LocalCluster: "cmtc-a"}, Metrics: metrics, Now: func() time.Time { return now }}
	return r, c, source, output, &now, reg
}
func reconcileProfile(t *testing.T, r *IssuerProfileReconciler) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err != nil {
		t.Fatal(err)
	}
}
func readProfile(t *testing.T, c client.Client, key client.ObjectKey) (*corev1.ConfigMap, *trustprofile.Publication) {
	t.Helper()
	var o corev1.ConfigMap
	if err := c.Get(context.Background(), key, &o); err != nil {
		t.Fatal(err)
	}
	p, err := trustprofile.DecodePublication([]byte(o.Data[trustprofile.DataKey]))
	if err != nil {
		t.Fatal(err)
	}
	return &o, p
}
func metricCount(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			match := true
			for k, v := range labels {
				found := false
				for _, label := range metric.Label {
					if label.GetName() == k && label.GetValue() == v {
						found = true
					}
				}
				match = match && found
			}
			if match {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}
func TestIssuerPublicationIdempotentRenewalAndTelemetryBoundary(t *testing.T) {
	r, c, _, _, now, reg := producerFixture(t)
	reconcileProfile(t, r)
	first, p := readProfile(t, c, r.Options.Output)
	if p.State != "published" || p.Sequence != 1 || p.AcceptedGeneration != 1 || p.Source.UID != "source-v1" || p.Source.ResourceVersion == "" {
		t.Fatalf("bad publication %+v", p)
	}
	expected := trustprofile.Expected{OutputUID: "output-v1", SourceUID: "source-v1", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, RootPins: r.Options.RootPins}
	if _, err := trustprofile.VerifyCurrent([]byte(first.Data[trustprofile.DataKey]), expected, *now); err != nil {
		t.Fatal(err)
	}
	reconcileProfile(t, r)
	second, _ := readProfile(t, c, r.Options.Output)
	if c.updates != 1 || first.ResourceVersion != second.ResourceVersion {
		t.Fatal("unchanged pass churned output")
	}
	*now = now.Add(16 * time.Second)
	reconcileProfile(t, r)
	_, renewed := readProfile(t, c, r.Options.Output)
	if renewed.Sequence != 2 || c.updates != 2 {
		t.Fatal("lease was not renewed")
	}
	if got := metricCount(t, reg, "cmtc_issuer_profile_publication_writes_total", map[string]string{"state": "published", "result": "acknowledged"}); got != 2 {
		t.Fatalf("acknowledged write count=%v", got)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if strings.Contains(family.GetName(), "trust_bundle_ready") || strings.Contains(family.GetName(), "protected") || strings.Contains(family.GetName(), "mtls") {
			t.Fatal("producer claimed consumer/datapath work")
		}
	}
}
func TestIssuerSourceDeletionUIDReplacementGenerationAndRecovery(t *testing.T) {
	r, c, source, _, _, _ := producerFixture(t)
	reconcileProfile(t, r)
	var original corev1.ConfigMap
	if err := c.Get(context.Background(), r.Options.Source, &original); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(context.Background(), &original); err != nil {
		t.Fatal(err)
	}
	reconcileProfile(t, r)
	out, p := readProfile(t, c, r.Options.Output)
	if p.State != "withdrawn" || p.Reason != "SourceDeleted" || p.Approval != nil || p.AcceptedGeneration != 1 {
		t.Fatal("source deletion retained trust or lost generation floor")
	}
	reconcileProfile(t, r)
	again, _ := readProfile(t, c, r.Options.Output)
	if again.ResourceVersion != out.ResourceVersion {
		t.Fatal("tombstone churned")
	}
	var approval trustprofile.Approval
	if err := json.Unmarshal([]byte(source.Data[trustprofile.ApprovalKey]), &approval); err != nil {
		t.Fatal(err)
	}
	replacement := sourceObject(t, approval, "source-v2")
	if err := c.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	reconcileProfile(t, r)
	_, p = readProfile(t, c, r.Options.Output)
	if p.Reason != "SourceUIDMismatch" {
		t.Fatal("name reuse accepted")
	}
	r.Options.SourceUID = "source-v2"
	reconcileProfile(t, r)
	_, p = readProfile(t, c, r.Options.Output)
	if p.Reason != "GenerationRollback" {
		t.Fatal("same generation under replacement UID accepted after tombstone")
	}
	if err := c.Delete(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	approval.Generation = 2
	replacement = sourceObject(t, approval, "source-v3")
	if err := c.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	r.Options.SourceUID = "source-v3"
	reconcileProfile(t, r)
	_, p = readProfile(t, c, r.Options.Output)
	if p.State != "published" || p.AcceptedGeneration != 2 || p.AcceptedSourceUID != "source-v3" {
		t.Fatal("approved higher-generation replacement did not recover")
	}
}
func TestIssuerWrongRootDuplicateKeyAndExpiryWithdraw(t *testing.T) {
	for _, mode := range []string{"wrongRoot", "duplicateKey", "expired"} {
		t.Run(mode, func(t *testing.T) {
			r, c, source, _, now, _ := producerFixture(t)
			switch mode {
			case "wrongRoot":
				r.Options.RootPins = []string{strings.Repeat("0", 64)}
			case "duplicateKey":
				var a trustprofile.Approval
				_ = json.Unmarshal([]byte(source.Data[trustprofile.ApprovalKey]), &a)
				a.Clusters[1].Issuers = a.Clusters[0].Issuers
				var existing corev1.ConfigMap
				_ = c.Get(context.Background(), r.Options.Source, &existing)
				_ = c.Delete(context.Background(), &existing)
				changed := sourceObject(t, a, "source-v1")
				if err := c.Create(context.Background(), changed); err != nil {
					t.Fatal(err)
				}
			case "expired":
				*now = now.Add(time.Hour)
			}
			reconcileProfile(t, r)
			_, p := readProfile(t, c, r.Options.Output)
			if p.State != "withdrawn" || p.Approval != nil {
				t.Fatal("invalid public material published")
			}
			if mode == "expired" && p.Reason != "SourceExpired" {
				t.Fatal("expired approval reason lost")
			}
			if mode == "wrongRoot" {
				var a trustprofile.Approval
				_ = json.Unmarshal([]byte(source.Data[trustprofile.ApprovalKey]), &a)
				r.Options.RootPins = []string{a.Roots[0].SHA256}
				reconcileProfile(t, r)
				_, p = readProfile(t, c, r.Options.Output)
				if p.State != "published" {
					t.Fatal("correct approved root did not recover")
				}
			}
		})
	}
}
func TestIssuerSourceFreshReadChangeAndAPIOutageLease(t *testing.T) {
	r, c, _, _, now, _ := producerFixture(t)
	reads := 0
	c.getHook = func(ctx context.Context, key client.ObjectKey, _ client.Object) error {
		if key == r.Options.Source {
			reads++
			if reads == 2 {
				var changed corev1.ConfigMap
				if err := c.Client.Get(ctx, key, &changed); err != nil {
					return err
				}
				changed.Labels = map[string]string{"metadata-change": "true"}
				return c.Client.Update(ctx, &changed)
			}
		}
		return nil
	}
	reconcileProfile(t, r)
	_, p := readProfile(t, c, r.Options.Output)
	if p.Reason != "SourceChanged" || p.Approval != nil {
		t.Fatal("changed source snapshot published")
	}
	c.getHook = nil
	reconcileProfile(t, r)
	out, _ := readProfile(t, c, r.Options.Output)
	expected := trustprofile.Expected{OutputUID: "output-v1", SourceUID: "source-v1", SourceNamespace: "cmtc-system", SourceName: "approval", Cluster: "cmtc-a", MinimumGeneration: 1, RootPins: r.Options.RootPins}
	*now = now.Add(31 * time.Second)
	if _, err := trustprofile.VerifyCurrent([]byte(out.Data[trustprofile.DataKey]), expected, *now); err == nil {
		t.Fatal("whole-API-outage old publication did not expire")
	}
	denied := apierrors.NewForbidden(schema.GroupResource{Resource: "configmaps"}, "approval", errors.New("denied"))
	c.getHook = func(_ context.Context, key client.ObjectKey, _ client.Object) error {
		if key == r.Options.Source {
			return denied
		}
		return nil
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{}); !apierrors.IsForbidden(err) {
		t.Fatalf("source error not returned: %v", err)
	}
	_, p = readProfile(t, c, r.Options.Output)
	if p.Reason != "SourceUnavailable" || p.Approval != nil {
		t.Fatal("API source failure retained valid trust")
	}
	c.getHook = nil
	reconcileProfile(t, r)
	_, p = readProfile(t, c, r.Options.Output)
	if p.State != "published" {
		t.Fatal("API recovery failed")
	}
}
func TestIssuerOutputCollisionCorruptionAndConflictPreserve(t *testing.T) {
	for _, mode := range []string{"foreignUID", "foreignData", "corrupt", "cleared", "missing", "conflict"} {
		t.Run(mode, func(t *testing.T) {
			r, c, _, _, _, _ := producerFixture(t)
			if mode == "foreignUID" {
				r.Options.OutputUID = "other"
			}
			if mode == "conflict" {
				c.updateHook = func(context.Context, client.Object) error {
					return apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, "publication", errors.New("conflict"))
				}
			} else if mode != "foreignUID" {
				var out corev1.ConfigMap
				_ = c.Client.Get(context.Background(), r.Options.Output, &out)
				switch mode {
				case "foreignData":
					out.Data = map[string]string{"unowned": "keep"}
				case "corrupt":
					out.Data = map[string]string{trustprofile.DataKey: "not-json"}
				case "cleared":
					out.Annotations = map[string]string{trustprofile.InitializedAnnotation: "true"}
				case "missing":
					if err := c.Client.Delete(context.Background(), &out); err != nil {
						t.Fatal(err)
					}
				}
				if mode != "missing" {
					if err := c.Client.Update(context.Background(), &out); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{}); err == nil {
				t.Fatal("unsafe output accepted")
			}
			if mode != "conflict" && c.updates != 0 {
				t.Fatal("unowned/corrupt output overwritten")
			}
			if mode == "conflict" {
				c.updateHook = nil
				reconcileProfile(t, r)
				_, p := readProfile(t, c, r.Options.Output)
				if p.Sequence != 1 {
					t.Fatal("failed write advanced sequence")
				}
			}
		})
	}
}
func TestIssuerCancelledBeforeWriteAndCommittedUnacknowledgedWrite(t *testing.T) {
	t.Run("beforeWrite", func(t *testing.T) {
		r, c, _, _, _, _ := producerFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		reads := 0
		c.getHook = func(_ context.Context, key client.ObjectKey, _ client.Object) error {
			if key == r.Options.Source {
				reads++
				if reads == 2 {
					cancel()
				}
			}
			return nil
		}
		if _, err := r.Reconcile(ctx, ctrl.Request{}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
		if c.updates != 0 {
			t.Fatal("cancelled context wrote publication")
		}
	})
	t.Run("serverCommittedClientLostAck", func(t *testing.T) {
		r, c, _, _, _, reg := producerFixture(t)
		c.updateHook = func(ctx context.Context, o client.Object) error {
			if err := c.Client.Update(ctx, o); err != nil {
				return err
			}
			return context.DeadlineExceeded
		}
		if _, err := r.Reconcile(context.Background(), ctrl.Request{}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		first, p := readProfile(t, c, r.Options.Output)
		if p.Sequence != 1 {
			t.Fatal("server commit not retained")
		}
		c.updateHook = nil
		reconcileProfile(t, r)
		second, _ := readProfile(t, c, r.Options.Output)
		if c.updates != 1 || first.ResourceVersion != second.ResourceVersion {
			t.Fatal("retry duplicated committed publication")
		}
		if metricCount(t, reg, "cmtc_issuer_profile_publication_writes_total", map[string]string{"state": "published", "result": "error"}) != 1 || metricCount(t, reg, "cmtc_issuer_profile_publication_writes_total", map[string]string{"state": "published", "result": "acknowledged"}) != 0 {
			t.Fatal("lost acknowledgment metrics claimed exact publication success")
		}
	})
}

func TestIssuerProducerPassHasBoundedAPIContext(t *testing.T) {
	r, c, _, _, _, _ := producerFixture(t)
	c.getHook = func(ctx context.Context, _ client.ObjectKey, _ client.Object) error {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 4*time.Second {
			t.Error("API call lacks bounded producer deadline")
			return errors.New("missing deadline")
		}
		<-ctx.Done()
		return ctx.Err()
	}
	started := time.Now()
	_, err := r.Reconcile(context.Background(), ctrl.Request{})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 6*time.Second || c.updates != 0 {
		t.Fatalf("pass did not stop at deadline: elapsed=%s err=%v writes=%d", time.Since(started), err, c.updates)
	}
}
func TestIssuerProducerManagerCancellationStopsBlockedRead(t *testing.T) {
	r, c, _, _, _, _ := producerFixture(t)
	entered := make(chan struct{})
	c.getHook = func(ctx context.Context, _ client.ObjectKey, _ client.Object) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (&issuerProfileRunner{reconciler: r}).Start(ctx) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("runner never started direct read")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("manager cancellation waited for poll/deadline")
	}
	if c.updates != 0 {
		t.Fatal("shutdown published trust")
	}
}

func TestIssuerProducerRestartRetainsPublishedSequenceFloor(t *testing.T) {
	r, c, _, _, now, _ := producerFixture(t)
	reconcileProfile(t, r)
	metrics, err := trustprofile.NewMetrics(prometheus.NewRegistry(), "cmtc-a")
	if err != nil {
		t.Fatal(err)
	}
	restarted := &IssuerProfileReconciler{Client: c, Reader: c, Options: r.Options, Metrics: metrics, Now: r.Now}
	reconcileProfile(t, restarted)
	if c.updates != 1 {
		t.Fatal("restart churned current valid output")
	}
	*now = now.Add(16 * time.Second)
	reconcileProfile(t, restarted)
	_, p := readProfile(t, c, r.Options.Output)
	if p.Sequence != 2 || p.AcceptedGeneration != 1 || p.AcceptedSourceUID != "source-v1" {
		t.Fatal("restart lost publication/generation floor")
	}
}

func TestIssuerProducerLogsEveryFailedPassWithoutPayloads(t *testing.T) {
	for _, failure := range []string{"foreignOutput", "corruptOutput"} {
		t.Run(failure, func(t *testing.T) {
			r, c, _, output, _, _ := producerFixture(t)
			const marker = "untrusted-payload-must-not-appear-in-logs"
			if failure == "foreignOutput" {
				output.Labels = nil
			} else {
				output.Data = map[string]string{trustprofile.DataKey: "{" + marker}
			}
			if err := c.Client.Update(context.Background(), output); err != nil {
				t.Fatal(err)
			}
			core, records := observer.New(zapcore.ErrorLevel)
			ctx := ctrl.LoggerInto(context.Background(), zapr.NewLogger(zap.New(core)))
			if _, err := r.Reconcile(ctx, ctrl.Request{}); err == nil {
				t.Fatal("invalid output accepted")
			}
			entries := records.FilterMessage("issuer-profile pass failed").All()
			if len(entries) != 1 {
				t.Fatalf("missing bounded failed-pass log: %#v", entries)
			}
			fields := entries[0].ContextMap()
			for _, key := range []string{"component", "attempt", "deadline", "elapsed", "backoff", "stage", "error"} {
				if _, ok := fields[key]; !ok {
					t.Fatalf("missing %s from failure log: %#v", key, fields)
				}
			}
			if fields["component"] != "issuer-profile-producer" || fields["stage"] != "reconcile" {
				t.Fatalf("incorrect failure boundary: %#v", fields)
			}
			if strings.Contains(fmt.Sprint(fields), marker) {
				t.Fatal("untrusted publication payload logged")
			}
			if c.updates != 0 {
				t.Fatal("failed ownership/parse check mutated output")
			}
		})
	}
}
