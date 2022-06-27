/*
Copyright 2022.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.

	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"

	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"

	"github.com/projectsyn/k8s-service-ca-controller/certs"
	"github.com/projectsyn/k8s-service-ca-controller/controllers"
	//+kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(extv1.AddToScheme(scheme))

	//+kubebuilder:scaffold:scheme
}

//+kubebuilder:rbac:groups=cert-manager.io,resources=issuers,verbs=get;list;watch;create;update;patch
//+kubebuilder:rbac:groups=cert-manager.io,resources=clusterissuers,verbs=get;list;watch;create;update;patch

//go:generate go run sigs.k8s.io/controller-tools/cmd/controller-gen object paths="./..."
//go:generate go run sigs.k8s.io/controller-tools/cmd/controller-gen rbac:roleName=k8s-service-ca-controller paths="./..."

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var caNamespace string
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&caNamespace, "ca-namespace", "cert-manager",
		"The namespace in which the controller will create the CA certificate. "+
			"For most setups, this should be the namespace in which cert-manager is deployed.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsAddr,
		Port:                   9443,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "238cfff4.syn.tools",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	initClient, err := initClient(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to setup init client")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()

	err = initializeServiceCA(ctx, initClient, setupLog, caNamespace)
	if err != nil {
		setupLog.Error(err, "unable to initialize service CA")
		os.Exit(1)
	}

	if err = (&controllers.ServiceReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Service")
		os.Exit(1)
	}

	// TODO: Ensure this is updated when the CA certificate gets renewed
	ca, err := certs.GetServiceCA(ctx, initClient, setupLog, caNamespace)
	if err != nil {
		setupLog.Error(err, "unable to fetch Service CA certificate data", "controller", "ConfigMap")
		os.Exit(1)
	}
	if err = (&controllers.ConfigMapReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		ServiceCA: ca,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "ConfigMap")
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func initClient(config *rest.Config) (client.Client, error) {
	return client.New(config, client.Options{Scheme: scheme})
}

func initializeServiceCA(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) error {
	cmcrd := extv1.CustomResourceDefinition{}
	if err := c.Get(ctx, client.ObjectKey{Name: "certificates.cert-manager.io"}, &cmcrd); err != nil {
		if errors.IsNotFound(err) {
			l.Error(err, "CRD `certificates.cert-manager.io` missing, exiting...")
			os.Exit(1)
		}
		// Return other errors
		return err
	}

	// Ensure that service CA exists
	return certs.EnsureCA(ctx, c, l, caNamespace)
}
