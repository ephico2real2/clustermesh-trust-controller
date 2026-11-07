//go:build linux

// Command cmtc-measure is the measurement loader of the CMTC node DaemonSet (ADR-005). It attaches the observe-only
// cgroup_skb programs of internal/measurement to the cgroups of the Pods that the node agent lists, and writes their
// counters into a snapshot file that the agent exports as metrics. It holds CAP_BPF and CAP_NET_ADMIN, no API token
// and no listener, and refuses to start with anything more.
//
// Every second it reads the agent's desired list, attaches and detaches Pods, reads the counters and writes the
// snapshot. It exits only when its own setup is wrong (capabilities, token, object); a kernel that refuses the
// programs or a Pod that cannot be attached shows in the snapshot and makes the plane not ready instead.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ephico2real2/clustermesh-trust-controller/internal/measurement"
	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

var sourceRevision = "development"

// serviceAccountToken is where kubelet mounts a Pod's API token. The DaemonSet mounts one in the agent only.
const serviceAccountToken = "/var/run/secrets/kubernetes.io/serviceaccount/token"

type config struct {
	desiredPath string
	snapshotDir string
	cgroupRoot  string
	statusPath  string
	tokenPath   string
	interval    time.Duration
}

func main() {
	c := config{statusPath: "/proc/self/status", tokenPath: serviceAccountToken, interval: time.Second}
	var desiredDir string
	var version bool
	flag.BoolVar(&version, "version", false, "Print the source revision and the embedded object, and exit")
	flag.StringVar(&desiredDir, "desired-dir", "", "Directory where the node agent writes "+measurement.DesiredFile)
	flag.StringVar(&c.snapshotDir, "snapshot-dir", "", "Directory where the loader writes "+measurement.SnapshotFile)
	flag.StringVar(&c.cgroupRoot, "cgroup-root", "/sys/fs/cgroup", "The host's cgroup v2 mount")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	if version {
		fmt.Printf("cmtc-measure revision=%s object=%s compiler=%q enforcementAvailable=false\n", sourceRevision,
			measurement.ObjectSHA256, measurement.ObjectCompiler)
		return
	}
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("measurement-loader")
	if desiredDir == "" || c.snapshotDir == "" {
		fmt.Fprintln(os.Stderr, "--desired-dir and --snapshot-dir are required")
		os.Exit(2)
	}
	c.desiredPath = filepath.Join(desiredDir, measurement.DesiredFile)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := run(ctx, log, c); err != nil {
		log.Error(err, "measurement loader stopped", "sourceRevision", sourceRevision, "enforcementAvailable", false)
		os.Exit(1)
	}
}

// checkPrivileges refuses to run with any capability beyond measurement.LoaderCapabilities, without one of them,
// or with an API token.
func checkPrivileges(statusPath, tokenPath string) error {
	status, err := os.ReadFile(statusPath)
	if err != nil {
		return err
	}
	caps, err := measurement.ParseCapabilitySets(status)
	if err != nil {
		return err
	}
	if err := measurement.CheckCapabilitySets(caps, measurement.LoaderCapabilities); err != nil {
		return err
	}
	if _, err := os.Stat(tokenPath); err == nil {
		return fmt.Errorf("refusing to start: an API token is mounted at %s; the loader must have no API access", tokenPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("refusing to start: cannot tell whether an API token is mounted at %s: %w", tokenPath, err)
	}
	return nil
}

func run(ctx context.Context, log logr.Logger, c config) error {
	if err := checkPrivileges(c.statusPath, c.tokenPath); err != nil {
		return err
	}
	spec, err := measurement.LoadSpec()
	if err != nil {
		return err
	}
	plane, err := measurement.OpenPlane(spec, c.cgroupRoot, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := plane.Close(); err != nil {
			log.Error(err, "measurement plane not closed cleanly", "stage", "close")
		}
		log.Info("measurement loader stopped; every program detached", "stage", "close", "enforcementAvailable", false)
	}()
	log.Info("measurement loader started", "stage", "start", "sourceRevision", sourceRevision,
		"object", measurement.ObjectSHA256, "compiler", measurement.ObjectCompiler,
		"capabilities", measurement.CapabilityNames(measurement.LoaderCapabilities), "cgroupRoot", c.cgroupRoot,
		"desired", c.desiredPath, "snapshotDir", c.snapshotDir, "enforcementAvailable", false)

	clock := measurement.SystemClock()
	problems := map[string]string{} // the last error of each stage, so that each change is logged once
	report := func(stage string, err error, msg string) {
		text := ""
		if err != nil {
			text = err.Error()
		}
		if problems[stage] == text {
			return
		}
		problems[stage] = text
		if err != nil {
			log.Error(err, msg, "stage", stage)
		} else {
			log.Info(stage+" recovered", "stage", stage)
		}
	}
	var desired measurement.Desired
	listed := false // until the agent writes its first list, the node's Pod addresses are unknown
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		// A missing or invalid desired list keeps the previous one: the agent may not have written it yet.
		d, err := measurement.ReadDesired(c.desiredPath)
		if err == nil {
			desired, listed = d, true
		}
		report("desired", err, "desired list not read; keeping the previous one")
		if listed {
			report("node-addresses", plane.SetNodeAddresses(desired.NodeAddresses), "node addresses not loaded")
		}
		now := time.Now()
		plane.Reconcile(desired.Pods, now)
		plane.Read(now)
		report("snapshot", writeSnapshot(plane, clock, c.snapshotDir), "snapshot not written")
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func writeSnapshot(plane *measurement.Plane, clock measurement.Clock, dir string) error {
	boot, err := clock.BootID()
	if err != nil {
		return err
	}
	mono, err := clock.Monotonic()
	if err != nil {
		return err
	}
	return measurement.WriteFileAtomic(dir, measurement.SnapshotFile, plane.Snapshot(boot, mono))
}
