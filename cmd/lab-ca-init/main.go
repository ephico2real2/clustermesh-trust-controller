// lab-ca-init generates a disposable cluster intermediate key inside its own cluster.
// Only the public CSR is printed; the private key is never exported to the CI runner.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func run() error {
	cluster := os.Getenv("CLUSTER_NAME")
	if cluster == "" {
		return fmt.Errorf("CLUSTER_NAME required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cluster + " disposable intermediate"}}, key)
	if err != nil {
		return err
	}
	public := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
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
	_, err = client.CoreV1().Secrets("cert-manager").Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "cluster-intermediate"}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(public)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
