package main

import (
	"errors"
	"net/url"

	"k8s.io/client-go/rest"
)

// API TLS/RBAC is the producer's configuration authority. This check does not
// authenticate a remote workload and never inspects or logs credential bytes.
func validateIssuerAPITransport(cfg *rest.Config) error {
	if cfg == nil {
		return errors.New("issuer producer requires explicit API configuration")
	}
	endpoint, err := url.Parse(cfg.Host)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || cfg.Insecure || cfg.Transport != nil || cfg.WrapTransport != nil {
		return errors.New("issuer producer requires standard verified HTTPS Kubernetes API transport")
	}
	certificate := (len(cfg.CertData) > 0 || cfg.CertFile != "") && (len(cfg.KeyData) > 0 || cfg.KeyFile != "")
	if cfg.BearerToken == "" && cfg.BearerTokenFile == "" && !certificate && cfg.ExecProvider == nil && cfg.AuthProvider == nil {
		return errors.New("issuer producer requires configured authenticated Kubernetes API credentials")
	}
	return nil
}
