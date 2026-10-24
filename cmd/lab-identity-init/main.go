// lab-identity-init creates test issuer and ADS TLS keys inside their cluster.
// It emits public CSRs only; neither private key is returned to the runner.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type publicRequests struct {
	ClusterIssuerCSR string `json:"clusterIssuerCSR"`
	ADSServerCSR     string `json:"adsServerCSR"`
}

func keyAndRequest(request *x509.CertificateRequest) ([]byte, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, request, key)
	if err != nil {
		return nil, "", err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func initialize(ctx context.Context, client kubernetes.Interface, cluster string, output io.Writer) error {
	if cluster == "" || len(validation.IsDNS1123Subdomain(cluster)) != 0 {
		return fmt.Errorf("CLUSTER_NAME must be a DNS subdomain")
	}
	issuerKey, issuerCSR, err := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " test cluster issuer"}})
	if err != nil {
		return err
	}
	adsKey, adsCSR, err := keyAndRequest(&x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " ADS server"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}})
	if err != nil {
		return err
	}
	for _, secret := range []*corev1.Secret{
		{ObjectMeta: metav1.ObjectMeta{Name: "cluster-intermediate", Namespace: "cert-manager"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"tls.key": issuerKey}},
		{ObjectMeta: metav1.ObjectMeta{Name: "cilium-ztunnel-secrets", Namespace: "kube-system"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"bootstrap-private.key": adsKey}},
	} {
		if _, err := client.CoreV1().Secrets(secret.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("create %s/%s: %w", secret.Namespace, secret.Name, err)
		}
	}
	return json.NewEncoder(output).Encode(publicRequests{ClusterIssuerCSR: issuerCSR, ADSServerCSR: adsCSR})
}

func run() error {
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
	return initialize(ctx, client, os.Getenv("CLUSTER_NAME"), os.Stdout)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
