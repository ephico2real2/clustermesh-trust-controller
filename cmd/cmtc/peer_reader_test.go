package main

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A peer whose API accepts the connection and never answers holds the first read in API discovery, which takes no
// context; the request timeout must end it.
func TestPeerReaderBoundsDiscoveryOfAPeerThatNeverAnswers(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		<-release
	}))
	t.Cleanup(func() { close(release); server.Close() })
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	file := filepath.Join(t.TempDir(), "kubeconfig")
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: peer
clusters: [{name: peer, cluster: {server: %q, certificate-authority-data: %s}}]
users: [{name: reader, user: {token: not-a-real-token}}]
contexts: [{name: peer, context: {cluster: peer, user: reader}}]
`, server.URL, base64.StdEncoding.EncodeToString(ca))
	if err := os.WriteFile(file, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	const timeout = 300 * time.Millisecond
	peer, err := peerReader("cmtc-b", file, scheme, timeout)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	err = peer.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-publication"}, &corev1.ConfigMap{})
	if elapsed := time.Since(started); err == nil || elapsed > 10*timeout {
		t.Fatalf("read of a peer that never answers: err=%v after %s, want an error within %s", err, elapsed, 10*timeout)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) == 0 || !strings.HasPrefix(paths[0], "/api") {
		t.Fatalf("first request %v, want API discovery", paths)
	}
}
