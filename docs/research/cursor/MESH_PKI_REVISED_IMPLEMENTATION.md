# Cursor two-cluster PKI implementation proposal

> Historical design input. This document is not an accepted implementation or a current runbook. Use [delivery status](../../agile/DELIVERY_STATUS.md) for measured results and open gates.

Session: `2358cd68-fbf8-4652-a025-5566243e07fd`. CLI model verified: Grok 4.7 256K Extra High. Proposal only. Primary review and local qualification are required.

The previous bootstrap reused the ClusterMesh issuer Secret, so it cannot be deployed. I’ll read the current lineage checks and initializer, then return a complete isolated PKI path.The existing ClusterMesh issuer stays untouched. The new SPIRE CA uses its own Secret and ClusterIssuer, and the orchestrator creates only missing owned objects. These tests were not executed.

`internal/trustprofile/profile.go` now accepts one cluster CA in `ChainPEM` and requires the SPIRE certificate to be signed by that parent. A direct-root profile is not the deployment shape. The producer stays off until you choose to publish this chain. Pod Ready, a registration, and an xDS ACK are not Protected.

The Cilium chart still renders SPIRE only when `authentication.mutual.spire.enabled` is true, and that flag rewrites `cilium-configmap.yaml` and the agent DaemonSet. This path does not Helm-upgrade Cilium. cert-manager v1.21.1 is required and not installed or upgraded here.

## `cmd/lab-identity-init/spire_ca.go`

```go
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

const (
	spireCASecret   = "cmtc-spire-cluster-ca"
	spireCAOwner    = "cmtc-lab-pki"
	spireOwnerLabel = "security.cmtc.io/pki-owner"
	spireClusterLbl = "security.cmtc.io/pki-cluster"
	spireRoleLabel  = "security.cmtc.io/pki-role"
	spireCSRNote    = "security.cmtc.io/public-csr"
)

type spireCARequest struct {
	SpireClusterCACSR string `json:"spireClusterCACSR"`
}

func initializeSPIREClusterCA(ctx context.Context, client kubernetes.Interface, cluster string, output io.Writer) error {
	if cluster == "" || len(validation.IsDNS1123Subdomain(cluster)) != 0 || cluster == "cmtc-mtls" {
		return fmt.Errorf("CLUSTER_NAME must be cmtc-a or cmtc-b")
	}
	if cluster != "cmtc-a" && cluster != "cmtc-b" {
		return fmt.Errorf("CLUSTER_NAME must be cmtc-a or cmtc-b")
	}
	secrets := client.CoreV1().Secrets("cert-manager")
	existing, err := secrets.Get(ctx, spireCASecret, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		key, csr, err := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " SPIRE cluster CA"}})
		if err != nil {
			return err
		}
		created := spireCASecretObject(cluster, key, csr)
		if _, err = secrets.Create(ctx, created, metav1.CreateOptions{}); err == nil {
			return writeSPIRECASR(output, csr)
		}
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create cert-manager/%s: %w", spireCASecret, err)
		}
		existing, err = secrets.Get(ctx, spireCASecret, metav1.GetOptions{})
	}
	if err != nil {
		return err
	}
	csr, err := reuseSPIREClusterCA(existing, cluster)
	if err != nil {
		return err
	}
	return writeSPIRECASR(output, csr)
}

func spireCASecretObject(cluster string, key []byte, csr string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: spireCASecret, Namespace: "cert-manager",
			Labels: map[string]string{
				spireOwnerLabel: spireCAOwner,
				spireClusterLbl: cluster,
				spireRoleLabel:  "spire-cluster-ca",
			},
			Annotations: map[string]string{spireCSRNote: csr},
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{"tls.key": key},
	}
}

func reuseSPIREClusterCA(secret *corev1.Secret, cluster string) (string, error) {
	if secret.Name != spireCASecret || secret.Namespace != "cert-manager" {
		return "", fmt.Errorf("refusing a secret other than cert-manager/%s", spireCASecret)
	}
	if secret.Labels[spireOwnerLabel] != spireCAOwner || secret.Labels[spireClusterLbl] != cluster || secret.Labels[spireRoleLabel] != "spire-cluster-ca" {
		return "", fmt.Errorf("conflict: existing SPIRE cluster CA has another owner")
	}
	for name := range secret.Data {
		if name != "tls.key" && name != "tls.crt" {
			return "", fmt.Errorf("conflict: SPIRE cluster CA secret has an unexpected field")
		}
	}
	csr, err := parseOneCSR(secret.Annotations[spireCSRNote])
	if err != nil {
		return "", fmt.Errorf("conflict: stored public CSR: %w", err)
	}
	if err := exactClusterCASubject(csr, cluster); err != nil {
		return "", err
	}
	if err := csrMatchesKey(secret.Data["tls.key"], csr); err != nil {
		return "", fmt.Errorf("conflict: stored key does not match stored CSR: %w", err)
	}
	return secret.Annotations[spireCSRNote], nil
}

func parseOneCSR(value string) (*x509.CertificateRequest, error) {
	rest := bytes.TrimSpace([]byte(value))
	block, rest := pem.Decode(rest)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 {
		return nil, fmt.Errorf("one CERTIFICATE REQUEST PEM block required")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("trailing PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if len(csr.Raw) == 0 || !bytes.Equal(csr.Raw, block.Bytes) {
		return nil, fmt.Errorf("CSR DER is not canonical")
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	return csr, nil
}

func exactClusterCASubject(csr *x509.CertificateRequest, cluster string) error {
	subject := csr.Subject
	if subject.CommonName != cluster+" SPIRE cluster CA" || len(subject.Organization) != 0 || len(subject.OrganizationalUnit) != 0 || len(subject.Country) != 0 || len(subject.Province) != 0 || len(subject.Locality) != 0 || len(subject.StreetAddress) != 0 || len(subject.PostalCode) != 0 || len(subject.Names) != 0 || len(subject.ExtraNames) != 0 {
		return fmt.Errorf("conflict: CSR subject is not the cluster CA common name")
	}
	if len(csr.DNSNames) != 0 || len(csr.EmailAddresses) != 0 || len(csr.IPAddresses) != 0 || len(csr.URIs) != 0 {
		return fmt.Errorf("conflict: cluster CA CSR has a SAN")
	}
	return nil
}

func csrMatchesKey(keyPEM []byte, csr *x509.CertificateRequest) error {
	block, rest := pem.Decode(bytes.TrimSpace(keyPEM))
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("cluster CA private key PEM is not one PKCS#8 block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return fmt.Errorf("cluster CA key cannot sign")
	}
	keyBytes, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	csrBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(keyBytes, csrBytes) {
		return fmt.Errorf("public keys differ")
	}
	return nil
}

func writeSPIRECASR(output io.Writer, csr string) error {
	if strings.Contains(csr, "PRIVATE KEY") {
		return fmt.Errorf("refusing to write a private key")
	}
	return json.NewEncoder(output).Encode(spireCARequest{SpireClusterCACSR: csr})
}

type EntryQuery interface {
	Show(context.Context) (string, int, error)
	Create(context.Context) (string, int, error)
}

func ConfirmAgentEntry(ctx context.Context, query EntryQuery, id string, selectors []string, deadline time.Duration, now func() time.Time, sleep func(time.Duration), logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	start := now()
	limit := start.Add(deadline)
	backoff := 200 * time.Millisecond
	for attempt := 1; ; attempt++ {
		elapsed := now().Sub(start)
		if !now().Before(limit) {
			logger.LogAttrs(ctx, slog.LevelError, "registration deadline", slog.String("stage", "entry-show"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.Duration("backoff", backoff), slog.String("error", "deadline exceeded"))
			return fmt.Errorf("registration deadline exceeded")
		}
		output, code, err := query.Show(ctx)
		if err == nil && code == 0 && exactEntry(output, id, selectors) {
			logger.LogAttrs(ctx, slog.LevelInfo, "registration confirmed", slog.String("stage", "entry-show"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.String("spiffeID", id))
			return nil
		}
		showErr := err
		if code != 0 && err == nil {
			showErr = fmt.Errorf("entry show exit %d", code)
		}
		logger.LogAttrs(ctx, slog.LevelWarn, "registration attempt", slog.String("stage", "entry-show"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.Duration("backoff", backoff), slog.String("error", errText(showErr)))
		if code == 0 && err == nil {
			_, createCode, createErr := query.Create(ctx)
			if createErr == nil && createCode == 0 {
				continue
			}
			logger.LogAttrs(ctx, slog.LevelWarn, "registration create", slog.String("stage", "entry-create"), slog.Int("attempt", attempt), slog.Duration("elapsed", now().Sub(start)), slog.Duration("deadline", deadline), slog.Duration("backoff", backoff), slog.String("error", errText(createErr)))
		}
		sleep(backoff)
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func exactEntry(output, id string, selectors []string) bool {
	if !strings.Contains(output, "Found 1 entry") || strings.Contains(output, "Found 0 entries") {
		return false
	}
	if !strings.Contains(output, "SPIFFE ID: "+id) && !strings.Contains(output, "SPIFFE ID        : "+id) {
		return false
	}
	for _, selector := range selectors {
		if !strings.Contains(output, selector) {
			return false
		}
	}
	return len(selectors) == 2
}

func errText(err error) string {
	if err == nil {
		return "exit status"
	}
	return err.Error()
}

func WaitTCP(ctx context.Context, address string, dial func(string) error, deadline time.Duration, now func() time.Time, sleep func(time.Duration), logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	start := now()
	limit := start.Add(deadline)
	backoff := 200 * time.Millisecond
	for attempt := 1; ; attempt++ {
		elapsed := now().Sub(start)
		if !now().Before(limit) {
			logger.LogAttrs(ctx, slog.LevelError, "server wait deadline", slog.String("stage", "tcp-ready"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.Duration("backoff", backoff), slog.String("error", "deadline exceeded"))
			return fmt.Errorf("SPIRE server readiness deadline exceeded")
		}
		if err := dial(address); err == nil {
			logger.LogAttrs(ctx, slog.LevelInfo, "server reachable", slog.String("stage", "tcp-ready"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.String("address", address))
			return nil
		} else {
			logger.LogAttrs(ctx, slog.LevelWarn, "server wait", slog.String("stage", "tcp-ready"), slog.Int("attempt", attempt), slog.Duration("elapsed", elapsed), slog.Duration("deadline", deadline), slog.Duration("backoff", backoff), slog.String("error", err.Error()))
		}
		sleep(backoff)
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

func dialTCP(address string) error {
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err
}
```

Replace `run` in `cmd/lab-identity-init/main.go` with this function. Leave `initialize` unchanged.

```go
func run() error {
	mode := os.Getenv("LAB_INIT_MODE")
	if mode == "" {
		mode = "legacy"
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	switch mode {
	case "legacy":
		return initialize(ctx, client, os.Getenv("CLUSTER_NAME"), os.Stdout)
	case "spire-cluster-ca":
		return initializeSPIREClusterCA(ctx, client, os.Getenv("CLUSTER_NAME"), os.Stdout)
	case "register-agent":
		return fmt.Errorf("register-agent is invoked with ConfirmAgentEntry by the pod wrapper")
	case "wait-server":
		return WaitTCP(ctx, os.Getenv("SPIRE_SERVER"), dialTCP, 60*time.Second, time.Now, time.Sleep, logger)
	default:
		return fmt.Errorf("LAB_INIT_MODE must be legacy, spire-cluster-ca, register-agent, or wait-server")
	}
}
```

The pod wrapper below is the in-cluster registration command. It is in the same file so the binary has one entry point.

```go
func runRegisterAgent(logger *slog.Logger) error {
	id := os.Getenv("SPIFFE_ID")
	selectors := []string{os.Getenv("SELECTOR_NS"), os.Getenv("SELECTOR_SA")}
	deadline := 60 * time.Second
	query := execEntryQuery{bin: os.Getenv("SPIRE_SERVER_BIN"), socket: os.Getenv("SPIRE_SOCKET")}
	return ConfirmAgentEntry(context.Background(), query, id, selectors, deadline, time.Now, time.Sleep, logger)
}

type execEntryQuery struct{ bin, socket string }

func (q execEntryQuery) Show(ctx context.Context) (string, int, error) {
	return runSPIRE(ctx, q.bin, "entry", "show", "-socketPath", q.socket, "-spiffeID", os.Getenv("SPIFFE_ID"))
}
func (q execEntryQuery) Create(ctx context.Context) (string, int, error) {
	args := []string{"entry", "create", "-socketPath", q.socket, "-spiffeID", os.Getenv("SPIFFE_ID"), "-selector", os.Getenv("SELECTOR_NS"), "-selector", os.Getenv("SELECTOR_SA"), "-node"}
	return runSPIRE(ctx, q.bin, args...)
}
```

`runSPIRE` must return combined stdout and the process exit code, and must not include the command environment in the error string. Use `exec.CommandContext` and `ExitError.ExitCode`. On a missing binary, return the exit error to `ConfirmAgentEntry`, which logs the stage and stops at the deadline.

Wire `register-agent` to `runRegisterAgent(logger)` instead of the placeholder error above. The placeholder in the first `run` switch is replaced by that call. Do not keep both.

## `cmd/lab-identity-init/spire_ca_test.go`

```go
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
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/kubernetes/fake"
)

func spirePair(t *testing.T, cluster string) ([]byte, string) {
	t.Helper()
	key, csr, err := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " SPIRE cluster CA"}})
	if err != nil {
		t.Fatal(err)
	}
	return key, csr
}

func TestSPIREClusterCARetryDoesNotMintASecondKey(t *testing.T) {
	client := fake.NewClientset()
	var first, second bytes.Buffer
	if err := initializeSPIREClusterCA(t.Context(), client, "cmtc-a", &first); err != nil {
		t.Fatal(err)
	}
	if err := initializeSPIREClusterCA(t.Context(), client, "cmtc-a", &second); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) || bytes.Contains(first.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("retry changed the CSR or leaked a key")
	}
	secret, err := client.CoreV1().Secrets("cert-manager").Get(t.Context(), spireCASecret, metav1.GetOptions{})
	if err != nil || secret.Labels[spireClusterLbl] != "cmtc-a" || len(secret.Data) != 1 {
		t.Fatal(err, secret)
	}
	creates := 0
	for _, action := range client.Actions() {
		if action.GetVerb() == "create" {
			creates++
		}
	}
	if creates != 1 {
		t.Fatal("retry created another secret", creates)
	}
	if _, err := client.CoreV1().Secrets("cert-manager").Get(t.Context(), "cluster-intermediate", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("SPIRE initializer touched the ClusterMesh secret")
	}
}

func TestSPIREClusterCACreateRaceReusesTheWinner(t *testing.T) {
	key, csr := spirePair(t, "cmtc-b")
	winner := spireCASecretObject("cmtc-b", key, csr)
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "secrets", func(clienttesting.Action) (bool, runtime.Object, error) {
		if err := client.Tracker().Add(winner); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(corev1.Resource("secrets"), spireCASecret)
	})
	var output bytes.Buffer
	if err := initializeSPIREClusterCA(t.Context(), client, "cmtc-b", &output); err != nil {
		t.Fatal(err)
	}
	var body spireCARequest
	if err := json.Unmarshal(output.Bytes(), &body); err != nil || body.SpireClusterCACSR != csr {
		t.Fatal("race published a different CSR", err, output.String())
	}
	stored, _ := client.CoreV1().Secrets("cert-manager").Get(t.Context(), spireCASecret, metav1.GetOptions{})
	if !bytes.Equal(stored.Data["tls.key"], key) {
		t.Fatal("race replaced the stored key")
	}
}

func TestSPIREClusterCARejectsForeignMismatchedAndUnknownFields(t *testing.T) {
	key, csr := spirePair(t, "cmtc-a")
	otherKey, _ := spirePair(t, "cmtc-a")
	cases := []*corev1.Secret{
		{ObjectMeta: metav1.ObjectMeta{Name: spireCASecret, Namespace: "cert-manager", UID: "foreign"}},
		spireCASecretObject("cmtc-a", otherKey, csr),
		func() *corev1.Secret {
			s := spireCASecretObject("cmtc-a", key, csr)
			s.Data["extra"] = []byte("not-a-key-name")
			return s
		}(),
		func() *corev1.Secret {
			s := spireCASecretObject("cmtc-a", key, csr+"\n-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n")
			return s
		}(),
	}
	for _, secret := range cases {
		client := fake.NewClientset(secret)
		var output bytes.Buffer
		if err := initializeSPIREClusterCA(t.Context(), client, "cmtc-a", &output); err == nil || output.Len() != 0 {
			t.Fatal("bad secret was accepted", err)
		}
		got, _ := client.CoreV1().Secrets("cert-manager").Get(t.Context(), spireCASecret, metav1.GetOptions{})
		if !bytes.Equal(got.Data["tls.key"], secret.Data["tls.key"]) || string(got.Data["extra"]) != string(secret.Data["extra"]) {
			t.Fatal("bad secret was modified")
		}
	}
}

type scriptedEntry struct {
	shows   []string
	creates int
}

func (s *scriptedEntry) Show(context.Context) (string, int, error) {
	if len(s.shows) == 0 {
		return "Found 0 entries\n", 0, nil
	}
	out := s.shows[0]
	s.shows = s.shows[1:]
	if strings.HasPrefix(out, "exit:") {
		return "", 1, errors.New(strings.TrimPrefix(out, "exit:"))
	}
	return out, 0, nil
}
func (s *scriptedEntry) Create(context.Context) (string, int, error) {
	s.creates++
	return "", 0, nil
}

func TestRegistrationIsBoundedIdempotentAndRestarts(t *testing.T) {
	id := "spiffe://cmtc-a.mesh.example/ns/cilium-spire/sa/spire-agent"
	selectors := []string{"k8s_psat:agent_ns:cilium-spire", "k8s_psat:agent_sa:spire-agent"}
	found := "Found 1 entry\nSPIFFE ID        : " + id + "\nSelector         : " + selectors[0] + "\nSelector         : " + selectors[1] + "\n"
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	clock := time.Unix(0, 0)
	now := func() time.Time { return clock }
	sleep := func(d time.Duration) { clock = clock.Add(d) }
	first := &scriptedEntry{shows: []string{"Found 0 entries\n", found}}
	if err := ConfirmAgentEntry(t.Context(), first, id, selectors, 5*time.Second, now, sleep, logger); err != nil || first.creates != 1 {
		t.Fatal(err, first.creates, logs.String())
	}
	restart := &scriptedEntry{shows: []string{found}}
	if err := ConfirmAgentEntry(t.Context(), restart, id, selectors, 5*time.Second, now, sleep, logger); err != nil || restart.creates != 0 {
		t.Fatal("restart created another entry", err, restart.creates)
	}
	failing := &scriptedEntry{shows: []string{"exit:connection refused"}}
	err := ConfirmAgentEntry(t.Context(), failing, id, selectors, time.Second, now, sleep, logger)
	if err == nil || !strings.Contains(logs.String(), "stage=entry-show") || !strings.Contains(logs.String(), "deadline=") || !strings.Contains(logs.String(), "backoff=") {
		t.Fatal(err, logs.String())
	}
	if strings.Contains(logs.String(), "PRIVATE KEY") {
		t.Fatal("registration log leaked key material")
	}
}
```

`slog` text format uses spaces around `=`. The assertion `stage=entry-show` may fail against `stage=entry-show` with the default handler, which prints `stage=entry-show` only when the value has no spaces. `slog` default text is `stage=entry-show`. That matches. If the handler quotes values, assert `stage` and `entry-show` as separate substrings instead of `stage=entry-show`. Use `strings.Contains(logs.String(), "stage") && strings.Contains(logs.String(), "entry-show")` so the test is not coupled to quoting.

The mismatched-key case uses `otherKey` with the first CSR. `reuseSPIREClusterCA` compares public keys and returns an error. Good.

The trailing-PEM case puts a second PEM block in the annotation. `parseOneCSR` rejects it. Good.

## `scripts/lab/pki/render_spire.py`

```python
#!/usr/bin/env python3
"""Standalone SPIRE objects. They are not a Cilium Helm render."""
import json
from copy import deepcopy

SERVER = "ghcr.io/spiffe/spire-server:1.15.5@sha256:584a9c5cc95b9457f5033e7e4488d603fffe5ec48a80c4dba14b05c5e1c2c384"
AGENT = "ghcr.io/spiffe/spire-agent:1.15.5@sha256:3652c732b0f0d36f4dd78394230a1b1cd0ddcc29548a46c67a996b1a78c14481"
LEGACY_IMAGE = "localhost/cmtc:issuer-7e606195f5"
LEGACY_SHA = "a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae"
CLUSTERS = {"cmtc-a": "cmtc-a.mesh.example", "cmtc-b": "cmtc-b.mesh.example"}
SECRET = "cmtc-spire-cluster-ca"
ISSUER = "cmtc-spire-issuer"
FORBIDDEN = {"cluster-intermediate", "cmtc-lab-intermediate", "cmtc-mtls"}

def labels(cluster, role):
    return {"security.cmtc.io/pki-owner": "cmtc-lab-pki", "security.cmtc.io/pki-cluster": cluster, "security.cmtc.io/pki-role": role}

def meta(name, namespace, cluster, role, extra=None):
    body = {"name": name, "labels": labels(cluster, role)}
    if namespace:
        body["namespace"] = namespace
    if extra:
        body.update(extra)
    return body

def server_conf(cluster, domain):
    return f'''server {{
  bind_address = "0.0.0.0"
  bind_port = "8081"
  socket_path = "/tmp/spire-server/private/api.sock"
  trust_domain = "{domain}"
  data_dir = "/run/spire/data"
  log_level = "INFO"
  ca_key_type = "rsa-4096"
  ca_subject = {{
    country = ["US"],
    organization = ["SPIRE"],
    common_name = "{cluster} SPIRE CA",
  }}
}}
plugins {{
  DataStore "sql" {{
    plugin_data {{
      database_type = "sqlite3"
      connection_string = "/run/spire/data/datastore.sqlite3"
    }}
  }}
  NodeAttestor "k8s_psat" {{
    plugin_data {{
      clusters = {{
        "{cluster}" = {{
          use_token_review_api_validation = true
          service_account_allow_list = ["cilium-spire:spire-agent"]
        }}
      }}
    }}
  }}
  KeyManager "disk" {{
    plugin_data {{ keys_path = "/run/spire/data/keys.json" }}
  }}
  UpstreamAuthority "cert-manager" {{
    plugin_data {{
      namespace = "cilium-spire"
      issuer_name = "{ISSUER}"
      issuer_kind = "ClusterIssuer"
      issuer_group = "cert-manager.io"
    }}
  }}
  Notifier "k8sbundle" {{
    plugin_data {{ namespace = "cilium-spire" }}
  }}
}}
health_checks {{
  listener_enabled = true
  bind_address = "0.0.0.0"
  bind_port = "8080"
  live_path = "/live"
  ready_path = "/ready"
}}
'''

def agent_conf(cluster, domain):
    return f'''agent {{
  data_dir = "/run/spire"
  log_level = "ERROR"
  server_address = "spire-server.cilium-spire.svc"
  server_port = "8081"
  socket_path = "/run/spire/sockets/agent.sock"
  trust_bundle_path = "/run/spire/bundle/bundle.crt"
  trust_domain = "{domain}"
}}
plugins {{
  NodeAttestor "k8s_psat" {{
    plugin_data {{ cluster = "{cluster}" }}
  }}
  KeyManager "memory" {{ plugin_data {{}} }}
  WorkloadAttestor "k8s" {{
    plugin_data {{ skip_kubelet_verification = true }}
  }}
}}
health_checks {{
  listener_enabled = true
  bind_address = "0.0.0.0"
  bind_port = "4251"
  live_path = "/live"
  ready_path = "/ready"
}}
'''

def documents(cluster, init_image):
    if cluster not in CLUSTERS or init_image in {LEGACY_IMAGE, LEGACY_SHA}:
        raise ValueError("cluster or initializer image is not usable")
    domain = CLUSTERS[cluster]
    agent_id = f"spiffe://{domain}/ns/cilium-spire/sa/spire-agent"
    ns = "cilium-spire"
    docs = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": meta(ns, None, cluster, "namespace")},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("spire-server", ns, cluster, "spire-server-sa")},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("spire-agent", ns, cluster, "spire-agent-sa")},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("lab-spire-ca-init", "cert-manager", cluster, "spire-ca-init-sa")},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("spire-server", ns, cluster, "spire-server-config"), "data": {"server.conf": server_conf(cluster, domain)}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("spire-agent", ns, cluster, "spire-agent-config"), "data": {"agent.conf": agent_conf(cluster, domain)}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta("spire-bundle", ns, cluster, "spire-bundle"), "data": {}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta("spire-server", ns, cluster, "spire-server-role"), "rules": [{"apiGroups": [""], "resources": ["configmaps"], "resourceNames": ["spire-bundle"], "verbs": ["get", "list", "patch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta("spire-upstreamauthority", ns, cluster, "spire-upstream-role"), "rules": [{"apiGroups": ["cert-manager.io"], "resources": ["certificaterequests"], "verbs": ["create", "get", "list", "watch", "delete"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta("lab-spire-ca-init", "cert-manager", cluster, "spire-ca-init-role"), "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [SECRET], "verbs": ["get", "create"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta("spire-server", ns, cluster, "spire-server-binding"), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "spire-server"}, "subjects": [{"kind": "ServiceAccount", "name": "spire-server", "namespace": ns}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta("spire-upstreamauthority", ns, cluster, "spire-upstream-binding"), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "spire-upstreamauthority"}, "subjects": [{"kind": "ServiceAccount", "name": "spire-server", "namespace": ns}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta("lab-spire-ca-init", "cert-manager", cluster, "spire-ca-init-binding"), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "lab-spire-ca-init"}, "subjects": [{"kind": "ServiceAccount", "name": "lab-spire-ca-init", "namespace": "cert-manager"}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": meta("cmtc-lab-spire-server", None, cluster, "spire-server-clusterrole"), "rules": [{"apiGroups": ["authentication.k8s.io"], "resources": ["tokenreviews"], "verbs": ["create"]}, {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}, {"apiGroups": [""], "resources": ["nodes", "nodes/proxy"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": meta("cmtc-lab-spire-server", None, cluster, "spire-server-clusterbinding"), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cmtc-lab-spire-server"}, "subjects": [{"kind": "ServiceAccount", "name": "spire-server", "namespace": ns}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": meta("cmtc-lab-spire-agent", None, cluster, "spire-agent-clusterrole"), "rules": [{"apiGroups": [""], "resources": ["pods", "nodes", "nodes/proxy"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": meta("cmtc-lab-spire-agent", None, cluster, "spire-agent-clusterbinding"), "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cmtc-lab-spire-agent"}, "subjects": [{"kind": "ServiceAccount", "name": "spire-agent", "namespace": ns}]},
        {"apiVersion": "v1", "kind": "Service", "metadata": meta("spire-server", ns, cluster, "spire-server-service"), "spec": {"selector": {"app": "spire-server"}, "ports": [{"name": "grpc", "port": 8081}, {"name": "http", "port": 8080}]}},
        {"apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer", "metadata": meta(ISSUER, None, cluster, "spire-issuer"), "spec": {"ca": {"secretName": SECRET}}},
        {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta("lab-spire-ca-init", "cert-manager", cluster, "spire-ca-init-job"), "spec": {"backoffLimit": 1, "template": {"spec": {"restartPolicy": "Never", "serviceAccountName": "lab-spire-ca-init", "containers": [{"name": "init", "image": init_image, "imagePullPolicy": "IfNotPresent", "command": ["/lab-identity-init"], "env": [{"name": "LAB_INIT_MODE", "value": "spire-cluster-ca"}, {"name": "CLUSTER_NAME", "value": cluster}]}]}}}},
        server(cluster, domain, agent_id, init_image),
        agent(cluster, init_image),
    ]
    for doc in docs:
        if doc["metadata"]["name"] in FORBIDDEN:
            raise ValueError("rendered object uses a ClusterMesh PKI name")
    return docs

def server(cluster, domain, agent_id, init_image):
    return {"apiVersion": "apps/v1", "kind": "StatefulSet", "metadata": meta("spire-server", "cilium-spire", cluster, "spire-server"), "spec": {
        "replicas": 1, "serviceName": "spire-server", "selector": {"matchLabels": {"app": "spire-server"}},
        "template": {"metadata": {"labels": {**labels(cluster, "spire-server"), "app": "spire-server"}}, "spec": {
            "serviceAccountName": "spire-server", "shareProcessNamespace": True,
            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
            "containers": [
                {"name": "spire-server", "image": SERVER, "imagePullPolicy": "IfNotPresent", "args": ["-config", "/run/spire/config/server.conf"], "volumeMounts": [
                    {"name": "spire-config", "mountPath": "/run/spire/config", "readOnly": True},
                    {"name": "spire-data", "mountPath": "/run/spire/data"},
                    {"name": "spire-server-socket", "mountPath": "/tmp/spire-server/private"}]},
                {"name": "register-agent", "image": init_image, "imagePullPolicy": "IfNotPresent", "command": ["/lab-identity-init"], "env": [
                    {"name": "LAB_INIT_MODE", "value": "register-agent"},
                    {"name": "SPIFFE_ID", "value": agent_id},
                    {"name": "SELECTOR_NS", "value": "k8s_psat:agent_ns:cilium-spire"},
                    {"name": "SELECTOR_SA", "value": "k8s_psat:agent_sa:spire-agent"},
                    {"name": "SPIRE_SERVER_BIN", "value": "/proc/1/root/opt/spire/bin/spire-server"},
                    {"name": "SPIRE_SOCKET", "value": "/proc/1/root/tmp/spire-server/private/api.sock"}]}
            ],
            "volumes": [
                {"name": "spire-config", "configMap": {"name": "spire-server"}},
                {"name": "spire-data", "emptyDir": {}},
                {"name": "spire-server-socket", "emptyDir": {}}
            ]
        }}
    }}

def agent(cluster, init_image):
    return {"apiVersion": "apps/v1", "kind": "DaemonSet", "metadata": meta("spire-agent", "cilium-spire", cluster, "spire-agent"), "spec": {
        "selector": {"matchLabels": {"app": "spire-agent"}},
        "template": {"metadata": {"labels": {**labels(cluster, "spire-agent"), "app": "spire-agent"}}, "spec": {
            "serviceAccountName": "spire-agent", "hostPID": True, "hostNetwork": True, "dnsPolicy": "ClusterFirstWithHostNet",
            "securityContext": {"runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000},
            "initContainers": [{"name": "wait-for-server", "image": init_image, "imagePullPolicy": "IfNotPresent", "command": ["/lab-identity-init"], "env": [
                {"name": "LAB_INIT_MODE", "value": "wait-server"},
                {"name": "SPIRE_SERVER", "value": "spire-server.cilium-spire.svc:8081"}]}],
            "containers": [{"name": "spire-agent", "image": AGENT, "imagePullPolicy": "IfNotPresent", "args": ["-config", "/run/spire/config/agent.conf"], "volumeMounts": [
                {"name": "spire-config", "mountPath": "/run/spire/config", "readOnly": True},
                {"name": "spire-bundle", "mountPath": "/run/spire/bundle"},
                {"name": "spire-agent-socket", "mountPath": "/run/spire/sockets"},
                {"name": "spire-token", "mountPath": "/var/run/secrets/tokens", "readOnly": True}]}],
            "volumes": [
                {"name": "spire-config", "configMap": {"name": "spire-agent"}},
                {"name": "spire-bundle", "configMap": {"name": "spire-bundle"}},
                {"name": "spire-agent-socket", "emptyDir": {}},
                {"name": "spire-token", "projected": {"sources": [{"serviceAccountToken": {"path": "spire-agent", "expirationSeconds": 600, "audience": "spire-server"}}]}}
            ]
        }}
    }}
```

The register container must not use `/proc/1/root` unless PID 1 is `spire-server`. With two containers, PID 1 is not a reliable server PID. `runRegisterAgent` has to find the process whose command is `spire-server` under `/proc`. Add that lookup in Go and pass the discovered binary and socket into `execEntryQuery`. The env values in the manifest are the suffix paths `/opt/spire/bin/spire-server` and `/tmp/spire-server/private/api.sock`, not a guessed PID.

```go
func findProcessRoot(command string) (string, error) {
    entries, err := os.ReadDir("/proc")
    if err != nil {
        return "", err
    }
    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }
        raw, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline")
        if err != nil || !bytes.Contains(raw, []byte(command)) {
            continue
        }
        return "/proc/" + entry.Name() + "/root", nil
    }
    return "", fmt.Errorf("spire-server process not found")
}
```

Call it on every attempt from `execEntryQuery`, with a bounded error returned to `ConfirmAgentEntry`. Do not sleep inside `findProcessRoot`.

## `scripts/lab/pki/safety.py`

```python
#!/usr/bin/env python3
"""Pure decisions for ownership, context, root files, and public certificates."""
import base64, hashlib, json, os, stat
from pathlib import Path

OWNER = "cmtc-lab-pki"
FORBIDDEN = {"cluster-intermediate", "cmtc-lab-intermediate"}

class Refusal(Exception):
    pass

def require_context(kubeconfig, context, cluster):
    data = json.loads(Path(kubeconfig).read_text()) if str(kubeconfig).endswith(".json") else __import__("yaml").safe_load(Path(kubeconfig).read_text())
    current = data.get("current-context")
    match = next((item for item in data.get("contexts", []) if item.get("name") == context), None)
    if match is None or context != "kind-" + cluster or cluster not in {"cmtc-a", "cmtc-b"}:
        raise Refusal("explicit context does not identify the requested cluster")
    named = match["context"]["cluster"]
    server = next(item["cluster"]["server"] for item in data["clusters"] if item["name"] == named)
    if not server.startswith("https://"):
        raise Refusal("cluster server is not HTTPS")
    return {"current": current, "context": context, "cluster": named, "server": server}

def same_nodes(expected, observed):
    exp = {(item["name"], item["uid"]) for item in expected}
    got = {(item["name"], item["uid"]) for item in observed}
    if not exp or exp != got:
        raise Refusal("node name/UID set changed")

def classify(obj, cluster, role):
    meta = obj["metadata"]
    labels = meta.get("labels") or {}
    if meta["name"] in FORBIDDEN:
        raise Refusal("refusing ClusterMesh PKI object " + meta["name"])
    if not meta.get("uid") or not meta.get("resourceVersion"):
        raise Refusal("object has no UID or resourceVersion")
    if labels.get("security.cmtc.io/pki-owner") != OWNER or labels.get("security.cmtc.io/pki-cluster") != cluster or labels.get("security.cmtc.io/pki-role") != role:
        raise Refusal("existing object " + meta["name"] + " has another owner")
    return meta["uid"], meta["resourceVersion"]

def delete_body(uid, resource_version):
    if not uid or not resource_version:
        raise Refusal("rollback requires UID and resourceVersion")
    return {"apiVersion": "v1", "kind": "DeleteOptions", "propagationPolicy": "Foreground", "preconditions": {"uid": uid, "resourceVersion": resource_version}}

def certificate_patch(uid, resource_version, pem_text):
    block = pem_text.strip().encode()
    if b"PRIVATE KEY" in block or not block.startswith(b"-----BEGIN CERTIFICATE-----") or block.count(b"-----BEGIN CERTIFICATE-----") != 1:
        raise Refusal("patch value is not one public certificate")
    encoded = base64.b64encode(block).decode()
    return [
        {"op": "test", "path": "/metadata/uid", "value": uid},
        {"op": "test", "path": "/metadata/resourceVersion", "value": resource_version},
        {"op": "add", "path": "/data/tls.crt", "value": encoded},
    ]

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def cilium_same(before, after):
    if before != after:
        raise Refusal("Cilium DaemonSet, config, or Helm release changed")
    for key in ("enable-ipsec", "enable-wireguard", "enable-ztunnel"):
        if before["config"].get(key) not in {None, "false"}:
            raise Refusal("encryption is enabled")

def direct_signer(certs, parent):
    """certs and parent are cryptography.x509.Certificate objects."""
    matches = [cert for cert in certs if cert.issuer == parent.subject and cert.signature and cert != parent]
    signed = []
    for cert in matches:
        try:
            parent.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        except Exception:
            continue
        signed.append(cert)
    # cryptography's Certificate.public_key().verify API differs by key type.
    # Callers use verify_direct() below instead of this sketch.
    return signed
```

The `direct_signer` sketch above is not the implementation. Use this function instead. It does not guess by list order and does not call a key-type-specific `verify` that may not exist.

```python
def verify_direct(bundle_pems, parent_pem):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    parent = x509.load_pem_x509_certificate(parent_pem.encode())
    certs = []
    rest = bundle_pems.encode()
    while b"-----BEGIN CERTIFICATE-----" in rest:
        start = rest.index(b"-----BEGIN CERTIFICATE-----")
        end = rest.index(b"-----END CERTIFICATE-----", start) + len(b"-----END CERTIFICATE-----")
        certs.append(x509.load_pem_x509_certificate(rest[start:end]))
        rest = rest[end:]
    signed = []
    for cert in certs:
        if cert.subject == parent.subject:
            continue
        if cert.issuer != parent.subject:
            continue
        if cert.verify_directly_issued_by(parent) is None:
            signed.append(cert)
    if len(signed) != 1:
        raise Refusal("bundle does not have one direct SPIRE signer")
    return signed[0].public_bytes(Encoding.PEM).decode()
```

`Certificate.verify_directly_issued_by` exists in cryptography 42 and returns None on success. The CMTC test environment may not have that package. The primary's Mac has OpenSSL. Keep the decision in `verify_direct_openssl(records)` where each record is `{subject, issuer, pubkey_sha256, signature_ok}` produced by the orchestrator from `openssl x509 -noout -subject -issuer -pubkey` and `openssl verify`. The test feeds records in reverse order:

```python
def select_direct(records, parent_subject, parent_pubkey):
    signed = [item for item in records if item["issuer"] == parent_subject and item["subject"] != parent_subject and item["signed_by_parent"]]
    if len(signed) != 1:
        raise Refusal("bundle does not have one direct SPIRE signer")
    if signed[0]["pubkey"] == parent_pubkey:
        raise Refusal("direct signer reuses the parent key")
    return signed[0]
```

`signed_by_parent` is the boolean result of `openssl verify -CAfile root.crt -untrusted parent.crt candidate.crt` for that one candidate, not for the concatenated bundle. The test sets the flag on the last record and a decoy first record with `signed_by_parent=False`. Order cannot select the decoy.

## `scripts/lab/pki/root_store.py`

```python
#!/usr/bin/env python3
import fcntl, os, stat
from pathlib import Path

class Refusal(Exception):
    pass

def open_root(path, repo_root, artifacts_root):
    root = Path(path)
    if not root.is_absolute():
        raise Refusal("root directory must be absolute")
    real = Path(os.path.realpath(root))
    for parent in (Path(repo_root).resolve(), Path(artifacts_root).resolve()):
        if real == parent or parent in real.parents:
            raise Refusal("root directory is inside the repo or artifacts")
    if root.exists() and root.is_symlink():
        raise Refusal("root directory is a symlink")
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid():
        raise Refusal("root directory mode or owner is not private")
    lock_path = root / "lock"
    if lock_path.is_symlink():
        raise Refusal("root lock is a symlink")
    handle = lock_path.open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise Refusal("root directory is locked by another initialization")
    return handle

def root_files(root):
    cert, key = Path(root) / "root.crt", Path(root) / "root.key"
    for path in (cert, key):
        if path.is_symlink():
            raise Refusal("root file is a symlink")
    if cert.exists() != key.exists():
        raise Refusal("root is half-initialized; refusing repair")
    if key.exists():
        mode = stat.S_IMODE(key.lstat().st_mode)
        if mode != 0o600 or key.lstat().st_uid != os.getuid():
            raise Refusal("root key mode or owner is not private")
    return cert, key
```

Creation writes `root.key.new` with mode 0600, fsync, then `os.replace` onto `root.key`, then the same for `root.crt`. It does not delete an existing key. A public-key mismatch between the existing pair raises `Refusal` and deletes nothing. The orchestrator compares `openssl pkey -pubout` and `openssl x509 -pubkey` in memory and does not write either command's output to the evidence directory.

## `scripts/lab/pki/orchestrate.py`

The orchestrator is the only deployment entry. It takes `--cluster`, `--context`, `--kubeconfig`, `--root-dir`, `--expect-nodes`, `--init-image`, and `--init-sha`. It refuses `LEGACY_SHA` and `LEGACY_IMAGE`.

Its client methods are `get`, `create`, `patch`, and `delete`. `secret_view` runs only this jsonpath:

```text
{.metadata.uid}
{.metadata.resourceVersion}
{.metadata.labels.security\.cmtc\.io/pki-owner}
{.metadata.labels.security\.cmtc\.io/pki-cluster}
{.metadata.labels.security\.cmtc\.io/pki-role}
{.metadata.annotations.security\.cmtc\.io/public-csr}
{range $k,$v := .data}{$k}{"\n"}{end}
```

The range prints key names. It does not print `$v`. There is no `-o json` and no `-o yaml` for a Secret. The CSR text is accepted only after the same one-block CSR checks the Go parser enforces. The returned view is a dict of those fields. It is not written to artifacts.

`preflight(docs, client, cluster)` calls `get` for every document. A missing object is planned as `create`. An existing object must pass `classify`. A foreign object raises `Refusal` before the first create. `cluster-intermediate` and `cmtc-lab-intermediate` are read only to prove the client was not asked to change them; they are not in `docs`.

`apply_plan` creates missing objects one at a time and records `{api, name, namespace, uid, resourceVersion}` from the create response. On the first failure it deletes that list in reverse with `delete_body`. Objects classified as reusable are not in the list. The cert-manager release and the Cilium release are not in the list.

Before any create, and again after SPIRE is ready, it records Cilium Helm values, Helm manifest, the `cilium` DaemonSet spec, and `cilium-config` data. `sha256_bytes` hashes each. `cilium_same` compares the two records. It also records pod namespace, name, and phase for the application namespaces and compares those lists. It does not delete pods.

The node check reads `--expect-nodes` and compares it with `kubectl --context <explicit> get nodes` projected to name and UID. It does not run `kubectl config use-context` or `config current-context`.

The root is opened with `open_root` before signing. An existing pair is reused only when the public keys match, `basicConstraints` has `CA:TRUE` and `pathlen` of at least 2, and `openssl x509 -checkend 0` succeeds. Otherwise the run stops. A new pair is created only when both files are absent. The key remains in `--root-dir`. The evidence directory receives `root.crt`, `cluster-ca.crt`, and later `spire-ca.crt`.

The certificate patch is `certificate_patch` against the viewed UID and resourceVersion. If the view's data-key list already contains `tls.crt`, the orchestrator reads only `{.data.tls\.crt}`, checks it is one certificate, and checks its public key against the CSR. It does not read `tls.key` and does not sign again.

SPIRE readiness is `WaitTCP` in the agent init and a bounded poll of StatefulSet `readyReplicas` and DaemonSet `numberReady`, 60 seconds, logged with stage, attempt, elapsed, deadline, backoff, and error. The bundle is then read from `data.bundle\.crt` only. `select_direct` chooses the parent-signed certificate. The evidence check requires that certificate's single URI to be `spiffe://<domain>` and its path length to be 0. A bundle that fails those checks is copied as public evidence and the run exits nonzero. It does not mark the cluster protected and it does not enable the issuer-profile producer.

## `scripts/lab/pki/test_pki.py`

The tests construct a `FakeKube` whose store is a dict. `create` assigns a UID and fails when the key exists. `delete` requires the UID and resourceVersion in the body. `secret_view` returns the projection and records the argv it was asked to build. A test fails if that argv contains `-o json`, `-o yaml`, or `tls.key`.

Cover these cases:

- PyYAML round-trip of both clusters. Every document has the owner labels. The init role's only secret name is `cmtc-spire-cluster-ca`. No document is named `cluster-intermediate` or `cmtc-lab-intermediate`. Images are the pinned SPIRE digests. Both pod security contexts are UID 1000. Socket volumes are `emptyDir`. The agent registration container has one node SPIFFE ID and two selectors. The server config has no `cilium-agent` or `cilium-operator` entry.
- A kubeconfig whose `current-context` is `other` still selects `kind-cmtc-a`, and the file's current context is unchanged after `require_context`.
- Node UID replacement raises `Refusal`.
- A foreign `cilium-spire` namespace fails preflight with zero creates.
- A store that already contains `cluster-intermediate` and `cmtc-lab-intermediate` still has those objects byte-for-byte after a successful SPIRE plan.
- The fourth create raises. Rollback deletes only the three created UIDs. A pre-seeded owned Secret remains.
- A second plan against the created objects performs zero creates and returns the same UIDs.
- Replacing the Secret UID, or giving it another cluster label, raises `Refusal` before patch.
- `certificate_patch` decoded value parses as one certificate. A value that is a PKCS#8 PEM fails before a patch exists.
- Root tests: symlink directory, symlink key, mode `0755`, wrong uid, key without cert, cert without key, second lock, and a reused pair whose public keys differ. None of those paths delete the surviving file.
- `select_direct` with a decoy first and the real signer second returns the signer. Two `signed_by_parent` records raise `Refusal`.
- Cilium fingerprints that differ, or `enable-ztunnel: "true"`, raise `Refusal`.
- Pod phase `Running` changing to `Pending` raises `Refusal`.

The Go tests cover the initializer race, foreign Secret, mismatched CSR, unknown field, trailing PEM, and registration exit, idempotence, and restart. No test is skipped. This session did not run them.

## Commands

```sh
cd /Users/olasumbo/gitRepos/clustermest-trust-controller
go test ./cmd/lab-identity-init -count=1
python3 scripts/lab/pki/test_pki.py
```

Build a new `linux/arm64` image only after both pass. Do not reuse binary `a6723c7813b6f52e49184503400742867da0be40b7d70d46ce41681f5b83d5ae` or image `localhost/cmtc:issuer-7e606195f5` for this Job. Import the archive into the existing kind nodes and verify the CRI config and the running `/lab-identity-init` hash.

```sh
python3 scripts/lab/pki/orchestrate.py \
  --cluster cmtc-a --context kind-cmtc-a \
  --kubeconfig "$KUBECONFIG" \
  --root-dir "$HOME/.cmtc/spire-root" \
  --expect-nodes "$HOME/.cmtc/cmtc-a-nodes.json" \
  --init-image <new-image> --init-sha <new-sha>
```

Repeat for `cmtc-b` with the same `--root-dir`. The second run reuses the root. It does not create another key.

## Remaining gates

The SPIRE upstream CSR may add extensions or a path length other than 0. The evidence check then fails closed. Workload entries are not created, and the agent socket is an `emptyDir`, so a pod outside the agent cannot use the Workload API. Cilium is not configured with `mesh-auth-spire-*`. The issuer-profile producer is not given this chain. Ztunnel, encryption, and the ClusterMesh guard stay closed. A verified public chain is not workload mTLS and not Protected.
