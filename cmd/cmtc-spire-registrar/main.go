//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/spireregistrar"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func load(path, pin string) (spireregistrar.Options, error) {
	var out spireregistrar.Options
	expected, err := hex.DecodeString(pin)
	if err != nil || len(expected) != sha256.Size {
		return out, errors.New("independent exact config SHA256 is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	if !info.Mode().IsRegular() {
		return out, errors.New("registrar approval is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return out, err
	}
	if len(data) > 65536 {
		return out, errors.New("registrar config exceeds bound")
	}
	digest := sha256.Sum256(data)
	if !bytes.Equal(expected, digest[:]) {
		return out, errors.New("registrar config differs from Pod-spec pin")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return out, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return out, errors.New("trailing registrar config data")
	}
	return out, out.Validate()
}
func verifiedAPIConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(cfg.Host)
	if err != nil || u.Scheme != "https" || u.Host == "" || cfg.Insecure || (cfg.CAFile == "" && len(cfg.CAData) == 0) || cfg.Transport != nil || cfg.WrapTransport != nil || cfg.Dial != nil {
		return nil, errors.New("registrar requires native verified Kubernetes HTTPS configuration")
	}
	cfg.Timeout = 5 * time.Second
	return cfg, nil
}
func run() error {
	var path, pin string
	flag.StringVar(&path, "config", "/etc/cmtc-registrar/approval.json", "Exact immutable administrator approval")
	flag.StringVar(&pin, "config-sha256", "", "Independently pinned approval bytes in Pod spec")
	flag.Parse()
	options, err := load(path, pin)
	if err != nil {
		return err
	}
	cfg, err := verifiedAPIConfig()
	if err != nil {
		return err
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return err
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return err
	}
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: ":18086", LeaderElection: false})
	if err != nil {
		return err
	}
	// Local transport uses the existing SPIRE private admin UDS. No network
	// plaintext, server-admin SVID, keys or admin socket are exported to Cilium.
	conn, err := grpc.NewClient("passthrough:///cmtc-local-spire-admin", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return spireregistrar.DialServerSocket(ctx, "/tmp/spire-server/private/api.sock", 1000)
	}))
	if err != nil {
		return err
	}
	defer conn.Close()
	runner := &spireregistrar.Runner{Registrar: spireregistrar.Registrar{Source: spireregistrar.Source{Reader: mgr.GetAPIReader(), Options: options}, Entries: entryv1.NewEntryClient(conn)}, Log: ctrl.Log.WithName("spire-registrar")}
	if err := mgr.Add(runner); err != nil {
		return err
	}
	if err := mgr.AddHealthzCheck("live", healthz.Ping); err != nil {
		return err
	}
	if err := mgr.AddReadyzCheck("exact-entry-readback", runner.Ready); err != nil {
		return err
	}
	return mgr.Start(ctrl.SetupSignalHandler())
}

var sourceRevision = "development"

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("cmtc-spire-registrar source=%s\n", sourceRevision)
		return
	}
	ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
