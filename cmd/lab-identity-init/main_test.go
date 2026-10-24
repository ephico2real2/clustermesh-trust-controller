package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInitializationEmitsOnlyBoundPublicRequests(t *testing.T) {
	client := fake.NewClientset()
	var output bytes.Buffer
	if err := initialize(t.Context(), client, "cmtc-mtls", &output); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output.Bytes(), []byte("PRIVATE KEY")) {
		t.Fatal("private key escaped to runner output")
	}
	var requests publicRequests
	if err := json.Unmarshal(output.Bytes(), &requests); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ namespace, name, key, csr string }{
		{"cert-manager", "cluster-intermediate", "tls.key", requests.ClusterIssuerCSR},
		{"kube-system", "cilium-ztunnel-secrets", "bootstrap-private.key", requests.ADSServerCSR},
	} {
		secret, err := client.CoreV1().Secrets(item.namespace).Get(t.Context(), item.name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(secret.Data) != 1 {
			t.Fatal("initializer must not add certificates or CA keys to the ADS Secret")
		}
		keyPEM, _ := pem.Decode(secret.Data[item.key])
		key, err := x509.ParsePKCS8PrivateKey(keyPEM.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		csrPEM, _ := pem.Decode([]byte(item.csr))
		csr, err := x509.ParseCertificateRequest(csrPEM.Bytes)
		if err != nil || csr.CheckSignature() != nil {
			t.Fatal("invalid public request", err)
		}
		secretPublic, _ := x509.MarshalPKIXPublicKey(key.(crypto.Signer).Public())
		requestPublic, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if !bytes.Equal(secretPublic, requestPublic) {
			t.Fatal("public request does not bind the cluster-held private key")
		}
		if item.key == "bootstrap-private.key" && (len(csr.DNSNames) != 1 || csr.DNSNames[0] != "localhost" || len(csr.IPAddresses) != 2) {
			t.Fatal("ADS certificate must authenticate the loopback endpoint")
		}
	}
}

func TestInitializationDoesNotReuseAnExistingIssuerKey(t *testing.T) {
	client := fake.NewClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cluster-intermediate", Namespace: "cert-manager"}})
	var output bytes.Buffer
	err := initialize(t.Context(), client, "cmtc-mtls", &output)
	if !apierrors.IsAlreadyExists(err) || output.Len() != 0 {
		t.Fatal("existing key must fail without publishing requests", err)
	}
	if _, err := client.CoreV1().Secrets("kube-system").Get(t.Context(), "cilium-ztunnel-secrets", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatal("partial initialization unexpectedly created the ADS Secret", err)
	}
}

func TestInitializationRejectsInvalidClusterNames(t *testing.T) {
	client := fake.NewClientset()
	var output bytes.Buffer
	if initialize(t.Context(), client, "../foreign", &output) == nil || output.Len() != 0 || len(client.Actions()) != 0 {
		t.Fatal("invalid cluster name reached Kubernetes or emitted a request")
	}
}
