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
	flag.BoolVar(&issuerEnabled, "issuer-profile-producer", false, "Opt-in public issuer approval producer; never enables workload enforcement")
	flag.StringVar(&issuerNamespace, "issuer-profile-namespace", "cmtc-system", "Explicit source/output namespace")
	flag.StringVar(&issuerSource, "issuer-profile-source", "cmtc-issuer-approval", "Immutable administrator-approved public source ConfigMap")
	flag.StringVar(&issuerOutput, "issuer-profile-output", "cmtc-issuer-publication", "Pre-created producer-owned public output ConfigMap")
	flag.StringVar(&issuerSourceUID, "issuer-profile-source-uid", "", "Required source object UID pin")
	flag.StringVar(&issuerOutputUID, "issuer-profile-output-uid", "", "Required pre-created output object UID pin")
	flag.StringVar(&issuerRoots, "issuer-profile-root-sha256", "", "Comma-separated installation-approved root certificate SHA256 pins")
	flag.Uint64Var(&issuerGeneration, "issuer-profile-minimum-generation", 1, "Minimum administered approval generation")
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
	configured := false
	flag.Visit(func(f *flag.Flag) {
		if strings.HasPrefix(f.Name, "issuer-profile-") && f.Name != "issuer-profile-producer" {
			configured = true
		}
	})
	if !issuerEnabled && configured {
		fmt.Fprintln(os.Stderr, "issuer profile flags require explicit issuer-profile-producer opt-in")
		os.Exit(2)
	}
	if issuerEnabled {
		if mode != "controller" {
			fmt.Fprintln(os.Stderr, "issuer profile producer is controller-mode only")
			os.Exit(2)
		}
		profileOptions.RootPins = strings.Split(issuerRoots, ",")
		if err := profileOptions.Validate(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
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
			must((&controller.IssuerProfileReconciler{Client: mgr.GetClient(), Reader: mgr.GetAPIReader(), Options: profileOptions, Metrics: profileMetrics}).SetupWithManager(mgr))
		}
	} else {
		must(mgr.Add(&agent.Inventory{Client: mgr.GetAPIReader(), Node: node, Metrics: m}))
	}
	must(mgr.AddHealthzCheck("ping", healthz.Ping))
	must(mgr.AddReadyzCheck("ping", healthz.Ping))
	ctrl.Log.Info("starting experimental CMTC", "cluster", cluster, "mode", mode, "issuerProfileProducer", issuerEnabled, "enforcementAvailable", false)
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
	}
	return options
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "CMTC stopped")
		os.Exit(1)
	}
}
