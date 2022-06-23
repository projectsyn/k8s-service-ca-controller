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

	"github.com/go-logr/logr"
	"github.com/projectsyn/k8s-service-ca-controller/certs"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	ServingCertLabelKey = "service.syn.tools/serving-cert-secret-name"
)

// ServiceReconciler reconciles a Service object
type ServiceReconciler struct {
	client.Client
	Scheme *runtime.Scheme
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
			// TODO: fail gracefully here, if a service for which
			// we don't manage a cert gets deleted
			if err := certs.DeleteCertificate(ctx, l, r.Client, req); err != nil {
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

	l.Info("Creating certificate for service")
	err = certs.CreateCertificate(ctx, l, r.Client, svc)
	if err != nil {
		return ctrl.Result{}, nil
	}

	secret := corev1.Secret{}
	res, err := certs.FetchSecretForService(ctx, r.Client, &svc, &secret)
	if !res.IsZero() {
		// Requeue request if Certificate isn't ready yet
		return res, nil
	}
	if err != nil {
		// Bail if we get an error trying to fetch the certificate
		// secret
		l.Error(err, "While fetching Certificate secret")
		return ctrl.Result{}, nil
	}

	return copySecret(ctx, l, r.Client, &secret, &svc, secretName)
}

func copySecret(ctx context.Context, l logr.Logger, c client.Client, secret *corev1.Secret, svc *corev1.Service, secretName string) (ctrl.Result, error) {
	l.Info("Copying secret to service namespace")
	secretKey := client.ObjectKey{
		Name:      secretName,
		Namespace: svc.Namespace,
	}
	s := corev1.Secret{}
	update := false
	if err := c.Get(ctx, secretKey, &s); err == nil {
		update = true
	}

	if update {
		l.Info("Secret exists already, updating data")
		svcSecret := s.DeepCopy()
		for k, v := range secret.Data {
			svcSecret.Data[k] = v
		}
		setOwningService(svcSecret, svc)
		err := c.Update(ctx, svcSecret)
		if err != nil {
			l.Error(err, "while updating copy of secret")
		}
		return ctrl.Result{}, err
	}

	// Create secret
	l.Info("Secret doesn't exist yet, creating")
	svcSecret := secret.DeepCopy()
	svcSecret.ResourceVersion = ""
	svcSecret.Name = secretName
	svcSecret.Namespace = svc.Namespace
	setOwningService(svcSecret, svc)

	err := c.Create(ctx, svcSecret)
	if err != nil {
		l.Error(err, "while creating copy of secret")
	}
	return ctrl.Result{}, err
}

func setOwningService(secret *corev1.Secret, svc *corev1.Service) {
	secret.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(svc, corev1.SchemeGroupVersion.WithKind("Service")),
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *ServiceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
