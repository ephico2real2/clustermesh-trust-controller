//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/datapath"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	ctrl "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

const sampleMaxAge = 3 * time.Second

// Set only by the reproducible image build; development binaries stay explicit.
var sourceRevision = "development"

type observation struct {
	sync.RWMutex
	count                     datapath.Count
	ready                     bool
	sampledAt                 time.Time
	packets, bytes, available *prometheus.Desc
}

func (s *observation) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.packets
	ch <- s.bytes
	ch <- s.available
}
func (s *observation) snapshot(now time.Time) (datapath.Count, bool) {
	s.RLock()
	count, ready, sampledAt := s.count, s.ready, s.sampledAt
	s.RUnlock()
	age := now.Sub(sampledAt)
	return count, ready && !sampledAt.IsZero() && age >= 0 && age <= sampleMaxAge
}
func (s *observation) Collect(ch chan<- prometheus.Metric) {
	count, ready := s.snapshot(time.Now())
	r := 0.0
	if ready {
		r = 1
	}
	ch <- prometheus.MustNewConstMetric(s.available, prometheus.GaugeValue, r)
	// No data after uncertainty/staleness. Copy state before sending to avoid a
	// slow scrape blocking the sampling writer while it holds the state mutex.
	if !ready {
		return
	}
	ch <- prometheus.MustNewConstMetric(s.packets, prometheus.CounterValue, float64(count.Packets))
	ch <- prometheus.MustNewConstMetric(s.bytes, prometheus.CounterValue, float64(count.Bytes))
}
func (s *observation) serveReadiness(w http.ResponseWriter, r *http.Request) {
	_, ready := s.snapshot(time.Now())
	if !ready {
		http.Error(w, "observer unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
func newObservation(c datapath.Config) *observation {
	labels := prometheus.Labels{"cluster": c.Cluster, "node": c.Node, "direction": c.Direction}
	return &observation{
		packets:   prometheus.NewDesc("cmtc_datapath_observer_packets_total", "Packets at selected TCX hook before Cilium verdict; not requests or mTLS proof.", nil, labels),
		bytes:     prometheus.NewDesc("cmtc_datapath_observer_bytes_total", "skb bytes at selected TCX hook before Cilium verdict.", nil, labels),
		available: prometheus.NewDesc("cmtc_datapath_observer_ready", "Last sample is fresh and attachment matches frozen test interface and baseline chain.", nil, labels),
	}
}
func decodeConfig(r io.Reader) (datapath.Config, error) {
	var c datapath.Config
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return c, errors.New("configuration must contain exactly one JSON object")
	}
	return c, c.Validate()
}
func main() {
	if err := run(); err != nil {
		ctrl.Log.Error(err, "observe-only datapath stopped")
		os.Exit(1)
	}
}
func run() (retErr error) {
	var cfgPath, addr, elfPath, healthCheck, metricsAddress string
	var version bool
	flag.BoolVar(&version, "version", false, "Print source revision and exit without attaching")
	flag.StringVar(&cfgPath, "config", "", "Required immutable node-specific JSON config")
	flag.StringVar(&elfPath, "elf", "/usr/share/cmtc/observer_bpfel.o", "Immutable packaged BPF ELF")
	flag.StringVar(&addr, "listen", "127.0.0.1:18082", "Node-local observer metric/health listener")
	flag.StringVar(&metricsAddress, "metrics-listen", "", "Opt-in metrics-only NODE_IP:18085 endpoint; empty disables exposure")
	flag.StringVar(&healthCheck, "health-check", "", "Probe only: ready or live")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	if version {
		fmt.Printf("cmtc-bpf-observer revision=%s enforcementAvailable=false\n", sourceRevision)
		return nil
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	if healthCheck != "" {
		path := "/readyz"
		if healthCheck == "live" {
			path = "/healthz"
		} else if healthCheck != "ready" {
			return errors.New("invalid probe kind")
		}
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://127.0.0.1:18082" + path)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("probe returned %s", resp.Status)
		}
		return nil
	}
	if addr != "127.0.0.1:18082" {
		return errors.New("observer lab profile requires loopback 127.0.0.1:18082")
	}
	f, err := os.Open(cfgPath)
	if err != nil {
		return err
	}
	defer f.Close()
	c, err := decodeConfig(f)
	if err != nil {
		return err
	}
	if c.Node != os.Getenv("NODE_NAME") || c.Cluster != os.Getenv("CLUSTER_NAME") {
		return errors.New("node or cluster differs from explicit deployment ownership")
	}
	elf, err := os.ReadFile(elfPath)
	if err != nil {
		return err
	}
	// Reserve the sole allowed listener before mutating any BPF attachment.
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("reserve observer listener: %w", err)
	}
	defer listener.Close()
	// Validate and reserve the separate metrics-only listener before BPF Open.
	metricsStarted := time.Now()
	metricsListener, err := openMetricsListener(metricsAddress, os.Getenv("NODE_IP"), net.Listen)
	if err != nil {
		ctrl.Log.Error(err, "metrics listener rejected", "stage", "metrics-listen", "attempt", 1, "elapsed", time.Since(metricsStarted), "component", "datapath-observer", "sourceRevision", sourceRevision, "cluster", c.Cluster, "node", c.Node, "enforcementAvailable", false)
		return err
	}
	if metricsListener != nil {
		defer metricsListener.Close()
	}

	log := ctrl.Log.WithName("datapath-observer")
	log.Info("starting observe-only datapath", "cluster", c.Cluster, "node", c.Node,
		"podUID", c.PodUID, "ifIndex", c.IfIndex, "direction", c.Direction, "enforcementAvailable", false)
	started := time.Now()
	o, err := datapath.Open(c, elf)
	if err != nil {
		log.Error(err, "attachment rejected", "stage", "attach", "attempt", 1, "elapsed", time.Since(started))
		return err
	}
	defer func() {
		if err := o.Close(); err != nil {
			log.Error(err, "observer cleanup failed", "stage", "detach")
			retErr = errors.Join(retErr, err)
		} else {
			log.Info("observer detached", "stage", "detach", "enforcementAvailable", false)
		}
	}()
	log.Info("observer attached", "stage", "attach", "attempt", 1, "elapsed", time.Since(started), "enforcementAvailable", false)
	state := newObservation(c)
	reg := prometheus.NewRegistry()
	if err := reg.Register(state); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/readyz", state.serveReadiness)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errs := make(chan error, 2)
	go func() {
		err := srv.Serve(listener)
		if !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	defer func() {
		state.Lock()
		state.ready = false
		state.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, srv.Shutdown(ctx))
	}()
	if metricsListener != nil {
		metricsServer := metricsHTTPServer(reg)
		go func() {
			if err := metricsServer.Serve(metricsListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errs <- err
			}
		}()
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			retErr = errors.Join(retErr, metricsServer.Shutdown(ctx))
		}()
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		count, err := o.Sample()
		state.Lock()
		state.ready = err == nil
		state.count = count
		state.sampledAt = time.Now()
		state.Unlock()
		if err != nil {
			return fmt.Errorf("observer lifecycle verification failed: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case <-ticker.C:
		}
	}
}
