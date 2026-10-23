package main

import (
	"flag"
	"fmt"
	"os"

	api "github.com/ephico2real2/clustermesh-trust-controller/api/v1alpha1"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/agent"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/controller"
	"github.com/ephico2real2/clustermesh-trust-controller/internal/telemetry"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
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
	scheme := runtime.NewScheme()
	must(corev1.AddToScheme(scheme))
	must(api.AddToScheme(scheme))
	options := ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: metricsAddress}, HealthProbeBindAddress: healthAddress, LeaderElection: mode == "controller", LeaderElectionID: "cmtc-controller.security.cmtc.io", LeaderElectionNamespace: "cmtc-system"}
	if mode == "node" {
		options.Cache.ByObject = map[client.Object]cache.ByObject{&corev1.Pod{}: {Field: fields.OneTermEqualSelector("spec.nodeName", node)}}
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	must(err)
	m := telemetry.New(metrics.Registry, cluster, node)
	if mode == "controller" {
		must((&controller.PolicyReconciler{Client: mgr.GetClient(), Metrics: m}).SetupWithManager(mgr))
	} else {
		must(mgr.Add(&agent.Inventory{Client: mgr.GetAPIReader(), Node: node, Metrics: m}))
	}
	must(mgr.AddHealthzCheck("ping", healthz.Ping))
	must(mgr.AddReadyzCheck("ping", healthz.Ping))
	ctrl.Log.Info("starting experimental observation only CMTC", "cluster", cluster, "mode", mode, "enforcementAvailable", false)
	must(mgr.Start(ctrl.SetupSignalHandler()))
}

func must(err error) {
	if err != nil {
		ctrl.Log.Error(err, "CMTC stopped")
		os.Exit(1)
	}
}
