package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"syscall"
	"time"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Report timing (ADR-012). The arbiter counts a report as fresh only after it saw ObservedAt change within its report
// age (controller.DefaultReportMaxAge, four heartbeats).
const (
	ReportInterval  = 10 * time.Second
	ReportHeartbeat = 30 * time.Second
)

// ConditionDelegateEntry reports whether this node's ztunnel has its SPIRE delegate entry. The node agent cannot see
// it without the SPIRE Admin API, which it must not have; the SPIRE registrar owns delegate entries.
const ConditionDelegateEntry = "DelegateEntryObserved"

// Files read and written by the node agent. The Cilium agent and ztunnel read pins.json at startup only (Cilium
// fork daemon/cmd/ztunnel_issuer_profile.go, ztunnel fork src/xds/issuer_profile.rs load_config); ztunnel commits
// profile-state.json before it acknowledges a publication (ztunnel fork src/tls/profile_checkpoint.rs).
const (
	pinsFile           = "pins.json"
	pinsPrevious       = "pins.json.previous"
	pinsNext           = ".pins.json.next"
	pinsPreviousNext   = ".pins.json.previous.next"
	checkpointFile     = "profile-state.json"
	maxPinsBytes       = 16 * 1024
	maxCheckpointBytes = 2 * 1024 * 1024
	checkpointVersion  = 2
)

// pinsKeys are the pins file's keys in the order the Cilium agent's struct declares them.
var pinsKeys = []string{"cluster", "node", "sourceNamespace", "sourceName", "sourceUID", "outputNamespace", "outputName", "outputUID", "rootPins", "minimumGeneration", "minimumSequence", "approvalDigestAtMinimum", "publicationDigestAtMinimum"}

// pins mirrors the Cilium agent's issuerProfileProbePins. Generation and sequence are canonical decimal strings.
type pins struct {
	Cluster                    string   `json:"cluster"`
	Node                       string   `json:"node"`
	SourceNamespace            string   `json:"sourceNamespace"`
	SourceName                 string   `json:"sourceName"`
	SourceUID                  string   `json:"sourceUID"`
	OutputNamespace            string   `json:"outputNamespace"`
	OutputName                 string   `json:"outputName"`
	OutputUID                  string   `json:"outputUID"`
	RootPins                   []string `json:"rootPins"`
	MinimumGeneration          string   `json:"minimumGeneration"`
	MinimumSequence            string   `json:"minimumSequence"`
	ApprovalDigestAtMinimum    string   `json:"approvalDigestAtMinimum"`
	PublicationDigestAtMinimum string   `json:"publicationDigestAtMinimum"`
}

// TrustReporter writes this node's NodeTrustReport: what the pins file holds, and the generation ztunnel's
// checkpoint accepts. With ManagePins it also adds the administrator's root pins to the pins file. It reads no
// Secret and has no SPIRE socket; it needs the pins directory and, read-only, ztunnel's checkpoint directory.
type TrustReporter struct {
	Client        client.Client
	Cluster, Node string
	PinsDir       string
	ManagePins    bool
	// RootPins are the root SHA-256 pins approved in the Helm values; ManagePins adds the missing ones.
	RootPins      []string
	CheckpointDir string
	// RequiredUID is the owner the Cilium agent and ztunnel require of the pins file: 0. Tests set their own.
	RequiredUID uint32
	Now         func() time.Time

	last    *api.NodeTrustReportStatus
	written time.Time
}

func (t *TrustReporter) NeedLeaderElection() bool { return false }

func (t *TrustReporter) now() time.Time {
	if t.Now != nil {
		return t.Now().UTC()
	}
	return time.Now().UTC()
}

func (t *TrustReporter) Start(ctx context.Context) error {
	log := ctrl.LoggerFrom(ctx).WithValues("component", "node-trust-report", "node", t.Node, "enforcementAvailable", false)
	ticker := time.NewTicker(ReportInterval)
	defer ticker.Stop()
	for {
		if err := t.Report(ctx); err != nil && ctx.Err() == nil {
			// A failed write leaves the last report to go stale, which the arbiter treats as a block.
			log.Error(err, "node trust report not written", "stage", "report", "backoff", ReportInterval)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Report observes the node and writes its report when the observation changed or a heartbeat is due.
func (t *TrustReporter) Report(ctx context.Context) error {
	now := t.now()
	status := api.NodeTrustReportStatus{Cluster: t.Cluster, Pins: t.pins(), Ztunnel: t.ztunnel(now)}
	delegate := metav1.Condition{Type: ConditionDelegateEntry, Status: metav1.ConditionUnknown, Reason: "NotObservable",
		Message: "the node agent has no SPIRE Admin API access; the SPIRE registrar owns ztunnel's delegate entry", LastTransitionTime: metav1.NewTime(now)}
	if t.last != nil && len(t.last.Conditions) == 1 {
		delegate.LastTransitionTime = t.last.Conditions[0].LastTransitionTime
	}
	status.Conditions = []metav1.Condition{delegate}
	if t.last != nil && t.last.Cluster == status.Cluster && reflect.DeepEqual(t.last.Pins, status.Pins) && reflect.DeepEqual(t.last.Ztunnel, status.Ztunnel) && now.Sub(t.written) < ReportHeartbeat {
		return nil
	}
	status.ObservedAt = metav1.NewTime(now)
	var report api.NodeTrustReport
	err := t.Client.Get(ctx, client.ObjectKey{Name: t.Node}, &report)
	switch {
	case apierrors.IsNotFound(err):
		report = api.NodeTrustReport{ObjectMeta: metav1.ObjectMeta{Name: t.Node}, Status: status}
		err = t.Client.Create(ctx, &report)
	case err == nil:
		report.Status = status
		err = t.Client.Update(ctx, &report)
	}
	if err != nil {
		return fmt.Errorf("write node trust report %s: %w", t.Node, err)
	}
	if t.last == nil || !reflect.DeepEqual(t.last.Pins, status.Pins) || !reflect.DeepEqual(t.last.Ztunnel, status.Ztunnel) {
		ctrl.LoggerFrom(ctx).Info("node trust report changed", "component", "node-trust-report", "node", t.Node, "stage", "report",
			"pins", status.Pins.State, "pinsSHA256", status.Pins.SHA256, "pinsMessage", status.Pins.Message,
			"ztunnel", status.Ztunnel.State, "observation", status.Ztunnel.Observation, "generation", status.Ztunnel.AcceptedGeneration, "ztunnelMessage", status.Ztunnel.Message)
	}
	t.last, t.written = &status, now
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readFile opens name without following a final symlink and checks it is a bounded regular file owned by uid that
// group and others cannot write, as the Cilium agent and ztunnel check the pins file.
func readFile(path string, uid uint32, limit int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uid || info.Mode().Perm()&0o022 != 0 || info.Size() > limit {
		return nil, fmt.Errorf("%s must be a regular file of at most %d bytes, owned by uid %d and not writable by group or others", filepath.Base(path), limit, uid)
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", filepath.Base(path), limit)
	}
	return data, nil
}

func canonicalPositive(s string) error {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n == 0 || strconv.FormatUint(n, 10) != s {
		return errors.New("positive canonical decimal required")
	}
	return nil
}

// decodePins applies the Cilium agent's decoder rules: one object, only the known keys, each once.
func decodePins(data []byte) (pins, error) {
	var p pins
	if len(data) == 0 || len(data) > maxPinsBytes {
		return p, errors.New("bounded pins required")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return p, errors.New("pins object required")
	}
	values := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return p, err
		}
		key, ok := token.(string)
		if !ok || !slices.Contains(pinsKeys, key) || values[key] != nil {
			return p, errors.New("unknown, duplicate or aliased pin " + fmt.Sprint(token))
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return p, err
		}
		values[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return p, errors.New("invalid pins object")
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return p, errors.New("one pins object required")
	}
	canonical, err := json.Marshal(values)
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(canonical, &p); err != nil {
		return p, err
	}
	if err := canonicalPositive(p.MinimumGeneration); err != nil {
		return p, fmt.Errorf("minimumGeneration: %w", err)
	}
	if err := canonicalPositive(p.MinimumSequence); err != nil {
		return p, fmt.Errorf("minimumSequence: %w", err)
	}
	return p, nil
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return slices.Compact(out)
}

// pins reads the pins file and, with ManagePins, adds the approved root pins. The file is never created: its floors
// are the installation's, set when the node joined. A root pin is never removed: ztunnel refuses a checkpoint whose
// origin lost a root (profile_checkpoint.rs added_root_pins), so a removal needs a reviewed migration.
func (t *TrustReporter) pins() api.PinsReport {
	path := filepath.Join(t.PinsDir, pinsFile)
	data, err := readFile(path, t.RequiredUID, maxPinsBytes)
	if errors.Is(err, os.ErrNotExist) {
		return api.PinsReport{State: api.PinsAbsent, Message: path + " does not exist; the node agent never creates it"}
	}
	if err != nil {
		return api.PinsReport{State: api.PinsInvalid, Message: err.Error()}
	}
	p, err := decodePins(data)
	if err == nil && (p.Cluster != t.Cluster || p.Node != t.Node) {
		err = fmt.Errorf("pins name cluster %q node %q, not %q %q", p.Cluster, p.Node, t.Cluster, t.Node)
	}
	if err != nil {
		return api.PinsReport{State: api.PinsInvalid, SHA256: digest(data), Message: err.Error()}
	}
	report := api.PinsReport{State: api.PinsReadOnly, SHA256: digest(data), RootSHA256: sortedUnique(p.RootPins)}
	if !t.ManagePins {
		return report
	}
	want := sortedUnique(append(slices.Clone(p.RootPins), t.RootPins...))
	for _, have := range p.RootPins {
		if !slices.Contains(t.RootPins, have) {
			report.State, report.Message = api.PinsWriteFailed, "refused: root pin "+have+" is not approved, and a root pin is never removed by the node agent"
			return report
		}
	}
	if reflect.DeepEqual(want, report.RootSHA256) {
		report.State = api.PinsUnchanged
		return report
	}
	p.RootPins = want
	body, err := json.Marshal(p)
	if err == nil {
		err = t.replacePins(data, body)
	}
	if err != nil {
		report.State, report.Message = api.PinsWriteFailed, err.Error()
		return report
	}
	back, err := readFile(path, t.RequiredUID, maxPinsBytes)
	if err == nil && !bytes.Equal(back, body) {
		err = errors.New("the pins file read back differs from the bytes written")
	}
	if err != nil {
		report.State, report.Message = api.PinsWriteFailed, "verify: "+err.Error()
		return report
	}
	return api.PinsReport{State: api.PinsWritten, SHA256: digest(back), RootSHA256: want, Message: "previous file kept as " + pinsPrevious}
}

// writeNew writes data to a new file in dir (mode 0644, fsynced). A leftover from an interrupted write is replaced.
func writeNew(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// replacePins keeps the current bytes as pins.json.previous, then renames the new file over pins.json: a reader sees
// the old file or the new one, never a partial one. The new file has no final newline, as the old one.
func (t *TrustReporter) replacePins(old, body []byte) error {
	if err := writeNew(t.PinsDir, pinsPreviousNext, old); err != nil {
		return fmt.Errorf("keep the previous pins: %w", err)
	}
	if err := os.Rename(filepath.Join(t.PinsDir, pinsPreviousNext), filepath.Join(t.PinsDir, pinsPrevious)); err != nil {
		return fmt.Errorf("keep the previous pins: %w", err)
	}
	if err := writeNew(t.PinsDir, pinsNext, body); err != nil {
		return fmt.Errorf("write the new pins: %w", err)
	}
	if err := os.Rename(filepath.Join(t.PinsDir, pinsNext), filepath.Join(t.PinsDir, pinsFile)); err != nil {
		return fmt.Errorf("replace the pins: %w", err)
	}
	dir, err := os.Open(t.PinsDir)
	if err != nil {
		return err
	}
	err = dir.Sync()
	if closeErr := dir.Close(); err == nil {
		err = closeErr
	}
	return err
}

// checkpoint is the part of ztunnel's ProfileCheckpoint (profile_checkpoint.rs, VERSION 2) the report needs. The
// envelope's checksum covers the exact bytes of state, so the bytes are hashed as stored, never re-encoded.
type checkpoint struct {
	Version uint32 `json:"version"`
	Origin  struct {
		Cluster  string   `json:"cluster"`
		Node     string   `json:"node"`
		RootPins []string `json:"root_pins"`
	} `json:"origin"`
	Observation             string `json:"observation"`
	AuthorityGeneration     uint64 `json:"authority_generation"`
	AuthorityApprovalDigest string `json:"authority_approval_digest"`
	ValidUntilUnix          int64  `json:"valid_until_unix"`
	Anchors                 *struct {
		Pins []struct {
			Domain         string `json:"domain"`
			CertificateDER string `json:"certificate_der"`
		} `json:"pins"`
	} `json:"anchors"`
}

func decodeCheckpoint(data []byte) (checkpoint, error) {
	var c checkpoint
	var envelope struct {
		State    json.RawMessage `json:"state"`
		Checksum string          `json:"checksum"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&envelope); err != nil {
		return c, fmt.Errorf("checkpoint envelope: %w", err)
	}
	if len(envelope.State) == 0 || digest(envelope.State) != envelope.Checksum {
		return c, errors.New("checkpoint integrity mismatch")
	}
	if err := json.Unmarshal(envelope.State, &c); err != nil {
		return c, fmt.Errorf("checkpoint state: %w", err)
	}
	if c.Version != checkpointVersion {
		return c, fmt.Errorf("unsupported checkpoint version %d", c.Version)
	}
	return c, nil
}

// ztunnel reads ztunnel's checkpoint. Accepted means ztunnel committed a Validated publication whose lease has not
// ended by this node's clock, the clock ztunnel itself uses.
func (t *TrustReporter) ztunnel(now time.Time) api.ZtunnelReport {
	path := filepath.Join(t.CheckpointDir, checkpointFile)
	data, err := readFile(path, t.RequiredUID, maxCheckpointBytes)
	if errors.Is(err, os.ErrNotExist) {
		return api.ZtunnelReport{State: api.ZtunnelAbsent, Message: path + " does not exist"}
	}
	if err == nil {
		var c checkpoint
		if c, err = decodeCheckpoint(data); err == nil {
			return t.ztunnelReport(c, now)
		}
	}
	return api.ZtunnelReport{State: api.ZtunnelInvalid, Message: err.Error()}
}

func (t *TrustReporter) ztunnelReport(c checkpoint, now time.Time) api.ZtunnelReport {
	if c.Origin.Cluster != t.Cluster || c.Origin.Node != t.Node {
		return api.ZtunnelReport{State: api.ZtunnelInvalid, Message: fmt.Sprintf("checkpoint names cluster %q node %q", c.Origin.Cluster, c.Origin.Node)}
	}
	report := api.ZtunnelReport{State: api.ZtunnelNotCurrent, Observation: c.Observation, AcceptedGeneration: c.AuthorityGeneration,
		ApprovalDigest: c.AuthorityApprovalDigest, LoadedRootSHA256: sortedUnique(c.Origin.RootPins)}
	if c.Anchors != nil {
		for _, p := range c.Anchors.Pins {
			der, err := base64.StdEncoding.DecodeString(p.CertificateDER)
			if err != nil {
				return api.ZtunnelReport{State: api.ZtunnelInvalid, Message: "checkpoint pin is not base64"}
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return api.ZtunnelReport{State: api.ZtunnelInvalid, Message: "checkpoint pin: " + err.Error()}
			}
			report.TrustedIssuers = append(report.TrustedIssuers, api.TrustedIssuer{TrustDomain: p.Domain, SPKISHA256: digest(cert.RawSubjectPublicKeyInfo)})
		}
		sort.Slice(report.TrustedIssuers, func(i, j int) bool {
			a, b := report.TrustedIssuers[i], report.TrustedIssuers[j]
			return a.TrustDomain < b.TrustDomain || a.TrustDomain == b.TrustDomain && a.SPKISHA256 < b.SPKISHA256
		})
	}
	switch {
	case c.Observation != "Validated" || c.Anchors == nil:
		report.Message = "the last committed publication is not Validated"
	case now.Unix() >= c.ValidUntilUnix:
		report.Message = "the last committed publication's lease ended at " + time.Unix(c.ValidUntilUnix, 0).UTC().Format(time.RFC3339)
	default:
		report.State = api.ZtunnelAccepted
	}
	return report
}
