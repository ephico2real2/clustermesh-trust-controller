package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// maxApprovalConfigBytes bounds the arbiter's configuration file; sixteen clusters with their names fit in a few KiB.
const maxApprovalConfigBytes = 64 * 1024

// ApprovalClusterConfig is one cluster of the mesh in the arbiter's configuration file. Kubeconfig names the file of
// the read-only credential for a peer cluster's API (ADR-012, cross-cluster path); the local cluster has none.
type ApprovalClusterConfig struct {
	ApprovalCluster
	Kubeconfig string `json:"kubeconfig,omitempty"`
}

// ApprovalConfig is the arbiter's configuration file, rendered by the chart (charts/cmtc, controller.issuerApproval)
// from the administrator's values. Durations are Go duration strings.
type ApprovalConfig struct {
	Namespace            string                  `json:"namespace"`
	Slots                []string                `json:"slots"`
	AdoptSource          string                  `json:"adoptSource,omitempty"`
	Output               string                  `json:"output"`
	RootConfigMap        string                  `json:"rootConfigMap"`
	CertManagerNamespace string                  `json:"certManagerNamespace"`
	RootIssuer           string                  `json:"rootIssuer"`
	SPIRENamespace       string                  `json:"spireNamespace"`
	SPIREConfigMap       string                  `json:"spireConfigMap"`
	RootSHA256           []string                `json:"rootSHA256"`
	MinimumGeneration    uint64                  `json:"minimumGeneration"`
	Horizon              string                  `json:"horizon"`
	RenewBefore          string                  `json:"renewBefore"`
	RetirementMargin     string                  `json:"retirementMargin"`
	ReportMaxAge         string                  `json:"reportMaxAge"`
	Clusters             []ApprovalClusterConfig `json:"clusters"`
}

// DecodeApprovalConfig decodes the configuration strictly (no unknown fields, one object) and returns the arbiter's
// options and, by cluster name, the kubeconfig path of each peer. Every peer needs a kubeconfig: without one its
// evidence and its node reports can never be read, so no generation could ever be written; that is refused at
// startup instead of blocking forever.
func DecodeApprovalConfig(data []byte, localCluster string) (IssuerApprovalOptions, map[string]string, error) {
	if len(data) == 0 || len(data) > maxApprovalConfigBytes {
		return IssuerApprovalOptions{}, nil, errors.New("bounded issuer approval configuration required")
	}
	var c ApprovalConfig
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return IssuerApprovalOptions{}, nil, fmt.Errorf("issuer approval configuration: %w", err)
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return IssuerApprovalOptions{}, nil, errors.New("issuer approval configuration: one object required")
	}
	if len(c.Slots) != 2 {
		return IssuerApprovalOptions{}, nil, errors.New("issuer approval configuration: exactly two slots required")
	}
	o := IssuerApprovalOptions{Namespace: c.Namespace, Slots: [2]string{c.Slots[0], c.Slots[1]}, AdoptSource: c.AdoptSource, Output: c.Output,
		RootConfigMap: c.RootConfigMap, CertManagerNamespace: c.CertManagerNamespace, RootIssuer: c.RootIssuer, SPIRENamespace: c.SPIRENamespace,
		SPIREConfigMap: c.SPIREConfigMap, LocalCluster: localCluster, RootPins: c.RootSHA256, MinimumGeneration: c.MinimumGeneration}
	for name, field := range map[string]struct {
		value string
		into  *time.Duration
	}{"horizon": {c.Horizon, &o.Horizon}, "renewBefore": {c.RenewBefore, &o.RenewBefore}, "retirementMargin": {c.RetirementMargin, &o.RetirementMargin}, "reportMaxAge": {c.ReportMaxAge, &o.ReportMaxAge}} {
		d, err := time.ParseDuration(field.value)
		if err != nil || d <= 0 {
			return IssuerApprovalOptions{}, nil, fmt.Errorf("issuer approval configuration: %s must be a positive duration", name)
		}
		*field.into = d
	}
	peers := map[string]string{}
	for _, cluster := range c.Clusters {
		o.Clusters = append(o.Clusters, cluster.ApprovalCluster)
		switch {
		case cluster.Name == localCluster && cluster.Kubeconfig != "":
			return IssuerApprovalOptions{}, nil, errors.New("issuer approval configuration: the local cluster takes no kubeconfig")
		case cluster.Name != localCluster && (cluster.Kubeconfig == "" || !filepath.IsAbs(cluster.Kubeconfig)):
			return IssuerApprovalOptions{}, nil, fmt.Errorf("issuer approval configuration: peer %q needs an absolute kubeconfig path", cluster.Name)
		case cluster.Name != localCluster:
			peers[cluster.Name] = cluster.Kubeconfig
		}
	}
	if err := o.Validate(); err != nil {
		return IssuerApprovalOptions{}, nil, fmt.Errorf("issuer approval configuration: %w", err)
	}
	return o, peers, nil
}

// LoadApprovalConfig reads the configuration file at path.
func LoadApprovalConfig(path, localCluster string) (IssuerApprovalOptions, map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return IssuerApprovalOptions{}, nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxApprovalConfigBytes+1))
	if err != nil {
		return IssuerApprovalOptions{}, nil, err
	}
	return DecodeApprovalConfig(data, localCluster)
}
