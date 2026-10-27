package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	labRoot  = strings.Repeat("a", 64)
	meshRoot = strings.Repeat("b", 64)
)

func pinsBody(t *testing.T, node string, roots ...string) []byte {
	t.Helper()
	body, err := json.Marshal(pins{Cluster: "cmtc-a", Node: node, SourceNamespace: "cmtc-system", SourceName: "cmtc-issuer-approval-g6",
		SourceUID: "e8320c32-79ff-4382-8702-78da8ef14567", OutputNamespace: "cmtc-system", OutputName: "cmtc-issuer-publication",
		OutputUID: "fbc7b3c2-00f1-4787-a149-fca76e274c4e", RootPins: roots, MinimumGeneration: "6", MinimumSequence: "1",
		ApprovalDigestAtMinimum: "", PublicationDigestAtMinimum: ""})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func reporter(t *testing.T) *TrustReporter {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"pins", "checkpoint"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &TrustReporter{Cluster: "cmtc-a", Node: "cmtc-a-worker", PinsDir: filepath.Join(dir, "pins"), CheckpointDir: filepath.Join(dir, "checkpoint"),
		RequiredUID: uint32(os.Getuid())}
}

func write(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

// The node agent reads the pins file with the consumers' rules and reports it; it never creates one.
func TestPinsAreReadWithTheConsumersRules(t *testing.T) {
	r := reporter(t)
	path := filepath.Join(r.PinsDir, pinsFile)
	if got := r.pins(); got.State != api.PinsAbsent {
		t.Fatalf("absent file: %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("the node agent created a pins file")
	}
	body := pinsBody(t, "cmtc-a-worker", labRoot, meshRoot)
	write(t, path, body, 0o644)
	got := r.pins()
	if got.State != api.PinsReadOnly || got.SHA256 != sum(body) || !reflect.DeepEqual(got.RootSHA256, []string{labRoot, meshRoot}) {
		t.Fatalf("valid file: %+v", got)
	}
	cases := map[string][]byte{
		"other node":       pinsBody(t, "cmtc-a-control-plane", labRoot),
		"unknown key":      []byte(`{"cluster":"cmtc-a","extra":1}`),
		"duplicate key":    []byte(`{"cluster":"cmtc-a","cluster":"cmtc-a"}`),
		"two objects":      append(append([]byte{}, body...), body...),
		"zero generation":  []byte(strings.Replace(string(body), `"minimumGeneration":"6"`, `"minimumGeneration":"0"`, 1)),
		"padded sequence":  []byte(strings.Replace(string(body), `"minimumSequence":"1"`, `"minimumSequence":"01"`, 1)),
		"numeric sequence": []byte(strings.Replace(string(body), `"minimumSequence":"1"`, `"minimumSequence":1`, 1)),
	}
	for name, data := range cases {
		write(t, path, data, 0o644)
		if got := r.pins(); got.State != api.PinsInvalid {
			t.Errorf("%s: %+v", name, got)
		}
	}
	write(t, path, body, 0o664)
	if got := r.pins(); got.State != api.PinsInvalid {
		t.Errorf("group-writable file: %+v", got)
	}
	write(t, filepath.Join(r.PinsDir, "real.json"), body, 0o644)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(r.PinsDir, "real.json"), path); err != nil {
		t.Fatal(err)
	}
	if got := r.pins(); got.State != api.PinsInvalid {
		t.Errorf("symlink: %+v", got)
	}
	other := *r
	other.RequiredUID = r.RequiredUID + 1
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	write(t, path, body, 0o644)
	if got := other.pins(); got.State != api.PinsInvalid {
		t.Errorf("file of another owner: %+v", got)
	}
}

// ManagePins adds an approved root: the old file is kept, the new one replaces it by rename with no final newline,
// and the next pass reports it unchanged. Removing a root pin is refused and the file is left as it was.
func TestManagedPinsAddARootAndNeverRemoveOne(t *testing.T) {
	r := reporter(t)
	r.ManagePins, r.RootPins = true, []string{meshRoot, labRoot}
	path := filepath.Join(r.PinsDir, pinsFile)
	old := pinsBody(t, "cmtc-a-worker", labRoot)
	write(t, path, old, 0o644)
	got := r.pins()
	want := pinsBody(t, "cmtc-a-worker", labRoot, meshRoot)
	if got.State != api.PinsWritten || got.SHA256 != sum(want) || !reflect.DeepEqual(got.RootSHA256, []string{labRoot, meshRoot}) {
		t.Fatalf("add a root: %+v", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, want) || strings.HasSuffix(string(data), "\n") {
		t.Fatalf("new file:\n%s", data)
	}
	if previous, err := os.ReadFile(filepath.Join(r.PinsDir, pinsPrevious)); err != nil || !reflect.DeepEqual(previous, old) {
		t.Fatalf("previous file not kept: %v %s", err, previous)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v %v", err, info.Mode())
	}
	for _, leftover := range []string{pinsNext, pinsPreviousNext} {
		if _, err := os.Lstat(filepath.Join(r.PinsDir, leftover)); !os.IsNotExist(err) {
			t.Errorf("temporary file %s left behind", leftover)
		}
	}
	if got := r.pins(); got.State != api.PinsUnchanged || got.SHA256 != sum(want) {
		t.Fatalf("second pass: %+v", got)
	}
	r.RootPins = []string{meshRoot}
	if got := r.pins(); got.State != api.PinsWriteFailed || !strings.Contains(got.Message, "never removed") {
		t.Fatalf("root removal: %+v", got)
	}
	if data, _ := os.ReadFile(path); !reflect.DeepEqual(data, want) {
		t.Fatal("a refused removal changed the file")
	}
}

type state struct {
	Version uint32 `json:"version"`
	Origin  struct {
		Cluster         string   `json:"cluster"`
		Node            string   `json:"node"`
		SourceNamespace string   `json:"source_namespace"`
		OutputNamespace string   `json:"output_namespace"`
		OutputName      string   `json:"output_name"`
		OutputUID       string   `json:"output_uid"`
		RootPins        []string `json:"root_pins"`
	} `json:"origin"`
	Floors                  json.RawMessage `json:"floors"`
	Observation             string          `json:"observation"`
	AuthorityGeneration     uint64          `json:"authority_generation"`
	AuthorityApprovalDigest string          `json:"authority_approval_digest"`
	PublishedUnix           int64           `json:"published_unix"`
	ValidUntilUnix          int64           `json:"valid_until_unix"`
	Anchors                 json.RawMessage `json:"anchors"`
}

// fixtureState is the v1 checkpoint ztunnel wrote for its own tests (ztunnel fork src/tls/profile-state-v1-f221f29.json),
// moved to version 2 the way ProfileCheckpointV1::migrate does.
func fixtureState(t *testing.T) (state, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/ztunnel-profile-state-v1-f221f29.json")
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		State state `json:"state"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	s := envelope.State
	s.Version = 2
	return s, raw
}

func envelope(t *testing.T, s state) []byte {
	t.Helper()
	body, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]any{"state": json.RawMessage(body), "checksum": sum(body)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The checksum covers ztunnel's exact state bytes: a file ztunnel wrote passes the integrity check (and is then
// refused only for its version), and one changed byte fails it.
func TestCheckpointIntegrityUsesTheStoredBytes(t *testing.T) {
	_, raw := fixtureState(t)
	if _, err := decodeCheckpoint(raw); err == nil || err.Error() != "unsupported checkpoint version 1" {
		t.Fatalf("ztunnel's own v1 file: %v", err)
	}
	tampered := []byte(strings.Replace(string(raw), `"authority_generation":7`, `"authority_generation":8`, 1))
	if _, err := decodeCheckpoint(tampered); err == nil || !strings.Contains(err.Error(), "integrity") {
		t.Fatalf("tampered file: %v", err)
	}
}

func TestZtunnelAcceptanceFromItsCheckpoint(t *testing.T) {
	r := reporter(t)
	s, _ := fixtureState(t)
	path := filepath.Join(r.CheckpointDir, checkpointFile)
	at := time.Unix(s.ValidUntilUnix-10, 0)
	if got := r.ztunnel(at); got.State != api.ZtunnelAbsent {
		t.Fatalf("absent: %+v", got)
	}
	write(t, path, envelope(t, s), 0o600)
	got := r.ztunnel(at)
	if got.State != api.ZtunnelAccepted || got.AcceptedGeneration != 7 || got.ApprovalDigest != s.AuthorityApprovalDigest || got.Observation != "Validated" ||
		!reflect.DeepEqual(got.LoadedRootSHA256, s.Origin.RootPins) || len(got.TrustedIssuers) != 2 {
		t.Fatalf("accepted: %+v", got)
	}
	var anchors struct {
		Pins []struct {
			Domain         string `json:"domain"`
			CertificateDER string `json:"certificate_der"`
		} `json:"pins"`
	}
	if err := json.Unmarshal(s.Anchors, &anchors); err != nil {
		t.Fatal(err)
	}
	der, _ := base64.StdEncoding.DecodeString(anchors.Pins[0].CertificateDER)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if want := (api.TrustedIssuer{TrustDomain: anchors.Pins[0].Domain, SPKISHA256: sum(cert.RawSubjectPublicKeyInfo)}); !reflect.DeepEqual(got.TrustedIssuers[0], want) {
		t.Fatalf("trusted issuer %+v, want %+v", got.TrustedIssuers[0], want)
	}
	if got := r.ztunnel(time.Unix(s.ValidUntilUnix, 0)); got.State != api.ZtunnelNotCurrent || got.AcceptedGeneration != 7 {
		t.Fatalf("lease ended: %+v", got)
	}
	withdrawn := s
	withdrawn.Observation = "SourceExpired"
	write(t, path, envelope(t, withdrawn), 0o600)
	if got := r.ztunnel(at); got.State != api.ZtunnelNotCurrent || got.Observation != "SourceExpired" {
		t.Fatalf("withdrawn: %+v", got)
	}
	other := s
	other.Origin.Node = "cmtc-a-control-plane"
	write(t, path, envelope(t, other), 0o600)
	if got := r.ztunnel(at); got.State != api.ZtunnelInvalid {
		t.Fatalf("other node's checkpoint: %+v", got)
	}
	write(t, path, []byte(`{"state":{},"checksum":"00","extra":1}`), 0o600)
	if got := r.ztunnel(at); got.State != api.ZtunnelInvalid {
		t.Fatalf("unknown envelope field: %+v", got)
	}
}

// A report is written when the observation changes or a heartbeat is due, and only then; its name is the node's.
func TestReportsAreWrittenOnChangeAndHeartbeat(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := api.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := reporter(t)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	r.Client, r.Now = c, func() time.Time { return now }
	ctx := context.Background()
	read := func() api.NodeTrustReport {
		var report api.NodeTrustReport
		if err := c.Get(ctx, client.ObjectKey{Name: "cmtc-a-worker"}, &report); err != nil {
			t.Fatal(err)
		}
		return report
	}
	if err := r.Report(ctx); err != nil {
		t.Fatal(err)
	}
	first := read()
	if first.Status.Cluster != "cmtc-a" || first.Status.Pins.State != api.PinsAbsent || first.Status.Ztunnel.State != api.ZtunnelAbsent ||
		len(first.Status.Conditions) != 1 || first.Status.Conditions[0].Status != "Unknown" {
		t.Fatalf("first report: %+v", first.Status)
	}
	now = now.Add(ReportInterval)
	if err := r.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if read().ResourceVersion != first.ResourceVersion {
		t.Fatal("an unchanged observation was written before the heartbeat")
	}
	write(t, filepath.Join(r.PinsDir, pinsFile), pinsBody(t, "cmtc-a-worker", labRoot), 0o644)
	if err := r.Report(ctx); err != nil {
		t.Fatal(err)
	}
	changed := read()
	if changed.Status.Pins.State != api.PinsReadOnly || changed.Status.ObservedAt.Equal(&first.Status.ObservedAt) {
		t.Fatalf("changed observation: %+v", changed.Status)
	}
	now = now.Add(ReportHeartbeat)
	if err := r.Report(ctx); err != nil {
		t.Fatal(err)
	}
	if beat := read(); beat.Status.ObservedAt.Equal(&changed.Status.ObservedAt) || !beat.Status.Conditions[0].LastTransitionTime.Equal(&first.Status.Conditions[0].LastTransitionTime) {
		t.Fatalf("heartbeat: %+v", beat.Status)
	}
}
