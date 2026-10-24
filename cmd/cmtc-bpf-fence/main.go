//go:build linux

// Prototype quarantine only. There is deliberately no grant or live-retire API.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
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
)

const maxConfigBytes = 16 * 1024
const sampleMaxAge = 3 * time.Second
const listenAddress = "127.0.0.1:18083"

var sourceRevision = "development"

type quarantine struct {
	sync.RWMutex
	count                 datapath.FenceCount
	sampled               time.Time
	verified              bool
	packets, bytes, ready *prometheus.Desc
}

func newQuarantine(c datapath.FenceConfig) *quarantine {
	labels := prometheus.Labels{"cluster": c.Cluster, "node": c.Node, "direction": c.Direction}
	return &quarantine{
		packets: prometheus.NewDesc("cmtc_datapath_fence_dropped_packets_total", "Packets rejected by the deny-only prototype; not connections, requests or mTLS proof.", nil, labels),
		bytes:   prometheus.NewDesc("cmtc_datapath_fence_dropped_bytes_total", "skb bytes rejected by the deny-only prototype.", nil, labels),
		ready:   prometheus.NewDesc("cmtc_datapath_fence_quarantine_verified", "A fresh sample verifies the committed deny attachment; never means Protected or mTLS.", nil, labels),
	}
}
func (q *quarantine) snapshot(now time.Time) (datapath.FenceCount, bool) {
	q.RLock()
	defer q.RUnlock()
	age := now.Sub(q.sampled)
	return q.count, q.verified && !q.sampled.IsZero() && age >= 0 && age <= sampleMaxAge
}
func (q *quarantine) set(c datapath.FenceCount, ready bool) {
	q.Lock()
	defer q.Unlock()
	q.count = c
	q.verified = ready
	q.sampled = time.Now()
}
func (q *quarantine) Describe(ch chan<- *prometheus.Desc) {
	ch <- q.packets
	ch <- q.bytes
	ch <- q.ready
}
func (q *quarantine) Collect(ch chan<- prometheus.Metric) {
	c, ok := q.snapshot(time.Now())
	v := 0.0
	if ok {
		v = 1
	}
	ch <- prometheus.MustNewConstMetric(q.ready, prometheus.GaugeValue, v)
	if ok {
		ch <- prometheus.MustNewConstMetric(q.packets, prometheus.CounterValue, float64(c.DroppedPackets))
		ch <- prometheus.MustNewConstMetric(q.bytes, prometheus.CounterValue, float64(c.DroppedBytes))
	}
}
func decodeConfig(r io.Reader) (datapath.FenceConfig, error) {
	var c datapath.FenceConfig
	data, err := io.ReadAll(io.LimitReader(r, maxConfigBytes+1))
	if err != nil {
		return c, err
	}
	if len(data) > maxConfigBytes {
		return c, errors.New("configuration exceeds16KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, err
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return c, errors.New("configuration requires exactly one JSON object")
	}
	return c, c.Validate()
}

func readELF(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > 4*1024*1024 {
		return nil, errors.New("invalid bounded ELF size")
	}
	return data, nil
}
func probe(kind string) error {
	path := "/readyz"
	if kind == "live" {
		path = "/healthz"
	} else if kind != "ready" {
		return errors.New("health-check must be ready or live")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + listenAddress + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe returned %s", resp.Status)
	}
	return nil
}
func main() {
	if err := run(); err != nil {
		slog.Error("deny-only quarantine process stopped", "error", err, "enforcementAvailable", false)
		os.Exit(1)
	}
}
func run() (retErr error) {
	var cfgPath, elfPath, healthCheck string
	var version, retire bool
	flag.StringVar(&cfgPath, "config", "", "Immutable node-specific JSON configuration")
	flag.StringVar(&elfPath, "elf", "/usr/share/cmtc/fence_bpfel.o", "Immutable packaged deny-only ELF")
	flag.StringVar(&healthCheck, "health-check", "", "Read-only ready/live probe")
	flag.BoolVar(&version, "version", false, "Read-only build identity")
	flag.BoolVar(&retire, "retire-defunct", false, "Remove exact committed pins only after old kernel TCX link proves defunct")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if version {
		fmt.Printf("cmtc-bpf-fence revision=%s mode=deny-only prototype=true enforcementAvailable=false\n", sourceRevision)
		return nil
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if healthCheck != "" {
		return probe(healthCheck)
	}
	f, err := os.Open(cfgPath)
	if err != nil {
		return err
	}
	cfg, err := decodeConfig(f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if os.Getenv("NODE_NAME") == "" || os.Getenv("CLUSTER_NAME") == "" || cfg.Node != os.Getenv("NODE_NAME") || cfg.Cluster != os.Getenv("CLUSTER_NAME") {
		return errors.New("explicit NODE_NAME/CLUSTER_NAME must match immutable configuration")
	}
	elf, err := readELF(elfPath)
	if err != nil {
		return err
	}
	if retire {
		started := time.Now()
		err = datapath.RetireDefunctFence(cfg, elf)
		if err != nil {
			slog.Error("defunct retirement rejected", "stage", "retire-defunct", "attempt", 1, "elapsed", time.Since(started), "error", err, "enforcementAvailable", false)
			return err
		}
		slog.Info("defunct pins retired", "stage", "retire-defunct", "attempt", 1, "elapsed", time.Since(started), "enforcementAvailable", false)
		return nil
	}
	// Bind before any mutation, so another serving instance cannot install first.
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	state := newQuarantine(cfg)
	registry := prometheus.NewRegistry()
	if err = registry.Register(state); err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := state.snapshot(time.Now()); !ok {
			http.Error(w, "quarantine unverified; not Protected", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	serveErr := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	defer func() {
		state.set(datapath.FenceCount{}, false)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		retErr = errors.Join(retErr, srv.Shutdown(ctx))
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	started := time.Now()
	stage := "adopt"
	fence, err := datapath.AdoptFence(cfg, elf)
	if errors.Is(err, datapath.ErrFenceNotInstalled) {
		stage = "install"
		fence, err = datapath.InstallFence(cfg, elf)
	}
	if err != nil {
		slog.Error("quarantine transaction not qualified", "stage", stage, "attempt", 1, "elapsed", time.Since(started), "error", err, "enforcementAvailable", false)
		if fence != nil {
			return errors.Join(err, holdPartial(ctx, fence))
		}
		return err
	}
	// Release only this process's FDs. Pins and the deny attachment outlive us.
	defer func() {
		releaseErr := fence.ReleaseProcess()
		slog.Info("process handles released; pins retained", "stage", "release", "attempt", 1, "elapsed", time.Since(started), "error", releaseErr, "enforcementAvailable", false)
		retErr = errors.Join(retErr, releaseErr)
	}()
	slog.Info("committed deny attachment verified", "stage", stage, "attempt", 1, "elapsed", time.Since(started), "cluster", cfg.Cluster, "node", cfg.Node, "namespaceUID", cfg.NamespaceUID, "podUID", cfg.PodUID, "enforcementAvailable", false)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	attempt := 1
	for {
		sample, sampleErr := fence.Account()
		attempt++
		if sampleErr != nil {
			state.set(datapath.FenceCount{}, false)
			slog.Error("quarantine verification failed; pins retained", "stage", "sample", "attempt", attempt, "elapsed", time.Since(started), "error", sampleErr, "enforcementAvailable", false)
			return sampleErr
		}
		state.set(sample, true)
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErr:
			return err
		case <-tick.C:
		}
	}
}

// If attach succeeded but pinning failed, never close the last owning FD while
// the kernel reports that exact link live. Remain explicitly NotReady. A real
// SIGKILL before pin remains an OPEN acceptance gap, not a persistent fence.
func holdPartial(ctx context.Context, f *datapath.Fence) error {
	started := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for attempt := 1; ; attempt++ {
		err := f.ReleaseProcess()
		if err == nil {
			return nil
		}
		if !errors.Is(err, datapath.ErrFenceUnpinnedLive) {
			return err
		}
		slog.Error("holding unpinned live deny FD; persistence unqualified", "stage", "partial-hold", "attempt", attempt, "elapsed", time.Since(started), "backoff", time.Second, "error", err, "enforcementAvailable", false)
		// SIGTERM is acknowledged as NotReady but cannot safely close a live unpinned
		// link. Keep serving health until the audited fixture is removed externally.
		select {
		case <-tick.C:
		case <-ctx.Done():
			<-tick.C
		}
	}
}
