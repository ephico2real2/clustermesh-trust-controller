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
	// The read runs in a goroutine so that a read the timeout does not end fails the test here, not at go test's
	// own timeout.
	started := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- peer.Get(context.Background(), client.ObjectKey{Namespace: "cmtc-system", Name: "cmtc-issuer-publication"}, &corev1.ConfigMap{})
	}()
	select {
	case err = <-done:
	case <-time.After(10 * timeout):
		t.Fatalf("read of a peer that never answers still runs after %s, want an error within %s", time.Since(started), 10*timeout)
	}
	if err == nil {
		t.Fatal("read of a peer that never answers succeeded")
	}
	mu.Lock()
	defer mu.Unlock()
	// The GET of the ConfigMap is under /api too, so only the exact path proves that discovery is the request that hung.
	if len(paths) != 1 || paths[0] != "/api" {
		t.Fatalf("requests %q, want one: API discovery (/api)", paths)
	}
}
