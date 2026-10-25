package main

import (
	"net/http"
	"testing"

	"k8s.io/client-go/rest"
)

func TestIssuerProducerRejectsUnauthenticatedAPIConfiguration(t *testing.T) {
	base := &rest.Config{Host: "https://kubernetes.default.svc", BearerTokenFile: "/run/serviceaccount/token"}
	if err := validateIssuerAPITransport(base); err != nil {
		t.Fatal(err)
	}
	if err := validateIssuerAPITransport(nil); err == nil {
		t.Fatal("nil config accepted")
	}
	for _, mode := range []string{"http", "noHost", "insecure", "customTransport", "wrappedTransport", "anonymous", "userinfo"} {
		t.Run(mode, func(t *testing.T) {
			cfg := rest.CopyConfig(base)
			switch mode {
			case "http":
				cfg.Host = "http://localhost:8080"
			case "noHost":
				cfg.Host = "https:///"
			case "insecure":
				cfg.Insecure = true
			case "customTransport":
				cfg.Transport = http.DefaultTransport
			case "wrappedTransport":
				cfg.WrapTransport = func(rt http.RoundTripper) http.RoundTripper { return rt }
			case "anonymous":
				cfg.BearerTokenFile = ""
			case "userinfo":
				cfg.Host = "https://user:password@api.example"
			}
			if err := validateIssuerAPITransport(cfg); err == nil {
				t.Fatal("unauthenticated/insecure API authority accepted")
			}
		})
	}
}
