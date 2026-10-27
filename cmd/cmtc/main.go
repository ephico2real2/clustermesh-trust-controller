package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/agent"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/controller"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/trustprofile"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var cluster, mode, node, metricsAddress, healthAddress string
	var issuerEnabled bool
	var issuerNamespace, issuerSource, issuerOutput, issuerSourceUID, issuerOutputUID, issuerRoots string
	var issuerGeneration uint64
	var approvalConfig, pinsDir, checkpointDir, nodeRoots string
	var trustReport, managePins bool
	flag.BoolVar(&issuerEnabled, "issuer-profile-producer", false, "Opt-in public issuer approval producer; never enables workload enforcement")
	flag.StringVar(&issuerNamespace, "issuer-profile-namespace", "cmtc-system", "Explicit source/output namespace")
	flag.StringVar(&issuerSource, "issuer-profile-source", "cmtc-issuer-approval", "Immutable administrator-approved public source ConfigMap")
	flag.StringVar(&issuerOutput, "issuer-profile-output", "cmtc-issuer-publication", "Pre-created producer-owned public output ConfigMap")
	flag.StringVar(&issuerSourceUID, "issuer-profile-source-uid", "", "Required source object UID pin")
	flag.StringVar(&issuerOutputUID, "issuer-profile-output-uid", "", "Required pre-created output object UID pin")
	flag.StringVar(&issuerRoots, "issuer-profile-root-sha256", "", "Comma-separated installation-approved root certificate SHA256 pins")
	flag.Uint64Var(&issuerGeneration, "issuer-profile-minimum-generation", 1, "Minimum administered approval generation")
	flag.StringVar(&approvalConfig, "issuer-approval-config", "", "Issuer approval arbiter configuration file (ADR-012); the producer then follows the arbiter's slots instead of a fixed source")
	flag.BoolVar(&trustReport, "node-trust-report", false, "Node mode: report this node's issuer pins and the approval generation its ztunnel accepts in a NodeTrustReport (ADR-012)")
	flag.StringVar(&pinsDir, "pins-dir", "/etc/cmtc/ztunnel-issuer-pins", "Node mode: directory of the issuer pins file the Cilium agent and ztunnel read")
	flag.StringVar(&checkpointDir, "checkpoint-dir", "/var/lib/cmtc/ztunnel-issuer-checkpoint", "Node mode: ztunnel's issuer-profile checkpoint directory, read only")
	flag.BoolVar(&managePins, "manage-pins", false, "Node mode: add the approved root pins to the pins file; never creates the file or removes a pin")
	flag.StringVar(&nodeRoots, "node-root-sha256", "", "Comma-separated installation-approved root certificate SHA256 pins the node agent adds with --manage-pins")
	flag.StringVar(&cluster, "cluster-name", "", "Required stable cluster name for bounded metric labels")
	flag.StringVar(&mode, "mode", "controller", "controller or node")
	flag.StringVar(&node, "node-name", os.Getenv("NODE_NAME"), "Node for inventory mode")
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8080", "Metrics listener; restrict access with NetworkPolicy")
	flag.StringVar(&healthAddress, "health-probe-bind-address", ":8081", "Health listener")
	logOpts := zap.Options{Development: false}
	logOpts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&logOpts)))
	if cluster == "" || (mode != "controller" && mode != "node") || (mode == "node" && node == "") {
		fmt.Fprintln(os.Stderr, "cluster-name and a valid mode are required; node mode also requires node-name")
		os.Exit(2)
	}
	profileOptions := controller.IssuerProfileOptions{Source: client.ObjectKey{Namespace: issuerNamespace, Name: issuerSource}, Output: client.ObjectKey{Namespace: issuerNamespace, Name: issuerOutput}, SourceUID: types.UID(issuerSourceUID), OutputUID: types.UID(issuerOutputUID), MinimumGeneration: issuerGeneration, LocalCluster: cluster}
	configured, fixedSource := false, false
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "issuer-profile-") && f.Name != "issuer-profile-producer" {
			configured = true
		}
		if f.Name == "issuer-profile-source" || f.Name == "issuer-profile-source-uid" {
			fixedSource = true
		}
	})
	if !issuerEnabled && (configured || approvalConfig != "") {
		fmt.Fprintln(os.Stderr, "issuer profile and issuer approval flags require explicit issuer-profile-producer opt-in")
		os.Exit(2)
	}
	if issuerEnabled {
		if mode != "controller" {
			fmt.Fprintln(os.Stderr, "issuer profile producer is controller-mode only")
			os.Exit(2)
		}
		profileOptions.RootPins = strings.Split(issuerRoots, ",")
		err := profileOptions.Validate()
		if approvalConfig != "" {
			// The arbiter names the producer's source on every pass; a fixed source would contradict it.
			if fixedSource {
				fmt.Fprintln(os.Stderr, "issuer-approval-config and a fixed issuer-profile-source cannot both be set")
				os.Exit(2)
			}
			profileOptions.Source, profileOptions.SourceUID = client.ObjectKey{}, ""
			err = profileOptions.ValidateFollowed()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if (trustReport || managePins) && mode != "node" || managePins && !trustReport {
		fmt.Fprintln(os.Stderr, "node-trust-report is node-mode only, and manage-pins requires it")
		os.Exit(2)
	}
	var nodeRootPins []string
	if managePins {
		nodeRootPins = strings.Split(nodeRoots, ",")
		if len(nodeRootPins) > 4 {
			fmt.Fprintln(os.Stderr, "manage-pins needs one to four node-root-sha256 pins")
			os.Exit(2)
		}
		for _, pin := range nodeRootPins {
			if !trustprofile.PinValid(pin) {
				fmt.Fprintln(os.Stderr, "manage-pins needs valid node-root-sha256 pins")
				os.Exit(2)
			}
		}
	}
	scheme := runtime.NewScheme()
	must(corev1.AddToScheme(scheme))
	must(api.AddToScheme(scheme))
	options := managerOptions(scheme, mode, node, metricsAddress, healthAddress)
	kubeConfig := ctrl.GetConfigOrDie()
	if issuerEnabled {
		must(validateIssuerAPITransport(kubeConfig))
	}
	mgr, err := ctrl.NewManager(kubeConfig, options)
	must(err)
	m := telemetry.New(metrics.Registry, cluster, node)
	if mode == "controller" {
		must((&controller.PolicyReconciler{Client: mgr.GetClient(), Metrics: m}).SetupWithManager(mgr))
		if issuerEnabled {
			profileMetrics, err := trustprofile.NewMetrics(metrics.Registry, cluster)
			must(err)
			producer := &controller.IssuerProfileReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Options: profileOptions, Metrics: profileMetrics}
			if approvalConfig != "" {
				arbiter, err := issuerApprovalArbiter(mgr, scheme, approvalConfig, cluster)
				must(err)
				producer.Follow = arbiter.FollowedSource
				must(arbiter.SetupWithManager(mgr))
			}
			must(producer.SetupWithManager(mgr))
		}
	} else {
		must(mgr.Add(&agent.Inventory{Client: mgr.GetAPIReader(), Node: node, Metrics: m}))
		if trustReport {
			must(mgr.Add(&agent.TrustReporter{Client: mgr.GetClient(), Cluster: cluster, Node: node, PinsDir: pinsDir, CheckpointDir: checkpointDir, ManagePins: managePins, RootPins: nodeRootPins}))
		}
	}
	must(mgr.AddHealthzCheck("ping", healthz.Ping))
	must(mgr.AddReadyzCheck("ping", healthz.Ping))
	ctrl.Log.Info("starting experimental CMTC", "cluster", cluster, "mode", mode, "issuerProfileProducer", issuerEnabled, "issuerApprovalArbiter", approvalConfig != "", "nodeTrustReport", trustReport, "managePins", managePins, "enforcementAvailable", false)
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

// managerOptions configures the controller's leader election so that the
// issuer-profile publication outlives a handover (see
// controller.LeaderLeaseDuration). The leader releases its lease when the
// manager stops; that is safe because main returns as soon as Start does.
func managerOptions(scheme *runtime.Scheme, mode, node, metricsAddress, healthAddress string) ctrl.Options {
	options := ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: metricsAddress}, HealthProbeBindAddress: healthAddress, LeaderElection: mode == "controller", LeaderElectionID: "cmtc-controller.security.cmtc.io", LeaderElectionNamespace: "cmtc-system"}
	if mode == "controller" {
		leaseDuration, renewDeadline, retryPeriod := controller.LeaderLeaseDuration, controller.LeaderRenewDeadline, controller.LeaderRetryPeriod
		options.LeaderElectionReleaseOnCancel = true
		options.LeaseDuration, options.RenewDeadline, options.RetryPeriod = &leaseDuration, &renewDeadline, &retryPeriod
	}
	if mode == "node" {
		options.Cache.ByObject = map[client.Object]cache.ByObject{&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", node)}}
		// The node agent reads and writes only its own NodeTrustReport: no informer over every node's report.
		options.Client.Cache = &client.CacheOptions{DisableFor: []client.Object{&api.NodeTrustReport{}}}
	}
	return options
}

// issuerApprovalArbiter builds the arbiter from its configuration file. Each peer cluster's API is read with the
// kubeconfig the file names (a read-only credential the administrator installed, ADR-012), through the same verified
// HTTPS transport rules as the local API, with a direct client: a peer that is down never blocks startup.
func issuerApprovalArbiter(mgr ctrl.Manager, scheme *runtime.Scheme, path, cluster string) (*controller.IssuerApprovalReconciler, error) {
	options, peerFiles, err := controller.LoadApprovalConfig(path, cluster)
	if err != nil {
		return nil, err
	}
	peers := map[string]client.Reader{}
	for name, file := range peerFiles {
		cfg, err := clientcmd.BuildConfigFromFlags("", file)
		if err != nil {
			return nil, fmt.Errorf("peer %s kubeconfig: %w", name, err)
		}
		if err := validateIssuerAPITransport(cfg); err != nil {
			return nil, fmt.Errorf("peer %s: %w", name, err)
		}
		peer, err := client.New(cfg, client.Options{Scheme: scheme})
		if err != nil {
			return nil, fmt.Errorf("peer %s client: %w", name, err)
		}
		peers[name] = peer
	}
	arbiterMetrics, err := trustprofile.NewArbiterMetrics(metrics.Registry, cluster)
	if err != nil {
		return nil, err
	}
	return &controller.IssuerApprovalReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Cache: mgr.GetCache(), Peers: peers, Options: options, Metrics: arbiterMetrics}, nil
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "CMTC stopped")
		os.Exit(1)
	}
}
