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

package controllers

import (
	"context"

	"github.com/projectsyn/k8s-service-ca-controller/certs"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

const (
	// ServingCertLabelKey is the label key which the controller reacts to
	// to create a secret. The label value is used as the secret name
	// for the generated Certificate.
	ServingCertLabelKey = "service.syn.tools/serving-cert-secret-name"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Scheme      *runtime.Scheme
	CANamespace string
}

//+kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
//+kubebuilder:rbac:groups="",resources=services/status,verbs=get
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;delete;update;patch
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cert-manager.io,resources=certificates/status,verbs=get;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ServiceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("namespace", req.Namespace, "name", req.Name)

	svc := corev1.Service{}
	err := r.Get(ctx, client.ObjectKey{
		Namespace: req.Namespace,
		Name:      req.Name,
	}, &svc)
	if err != nil {
		if errors.IsNotFound(err) {
			// DeleteSecret is a noop if no secret labeled with
			// the deleted service's name is found.
			if err := certs.DeleteSecret(ctx, l, r.Client, req); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{}, nil
		}

		return ctrl.Result{}, err
	}

	labels := svc.Labels
	if labels == nil {
		// nothing to do if service has no labels
		return ctrl.Result{}, nil
	}
	secretName, ok := labels[ServingCertLabelKey]
	if !ok {
		// nothing to do, if the service isn't labeled
		return ctrl.Result{}, nil
	}

	l.V(1).Info("Reconciling Service CA")
	_, err = certs.GetServiceCA(ctx, r.Client, l, r.CANamespace)
	if err != nil {
		l.Info("Service CA not ready yet, requeuing request")
		return ctrl.Result{
			Requeue: true,
		}, err
	}

	l.V(1).Info("Reconciling certificate for service")

	err = certs.CreateCertificate(ctx, l, r.Client, svc, secretName)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		// Trigger reconcile for the service if the owned Certificate
		// is modified/deleted
		Owns(&cmapi.Certificate{}).
		Complete(r)
}
