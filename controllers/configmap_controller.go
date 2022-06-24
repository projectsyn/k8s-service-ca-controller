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
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	InjectLabelKey = "service.syn.tools/inject-ca-bundle"
)

// ConfigMapReconciler reconciles a ConfigMap object
type ConfigMapReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	ServiceCA string
}

//+kubebuilder:rbac:groups=core,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=core,resources=configmaps/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=core,resources=configmaps/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ConfigMapReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx).WithValues("namespace", req.Namespace, "name", req.Name)

	cm := corev1.ConfigMap{}
	err := r.Get(ctx, client.ObjectKey{
		Name:      req.Name,
		Namespace: req.Namespace,
	}, &cm)
	if err != nil {
		if errors.IsNotFound(err) {
			// nothing to do
			return ctrl.Result{}, nil
		}

		l.Error(err, "while fetching configmap")
		return ctrl.Result{}, err
	}

	cmLabels := cm.Labels
	if cmLabels == nil {
		// nothing to do, exit
		return ctrl.Result{}, nil
	}

	inject, ok := cmLabels[InjectLabelKey]
	if !ok {
		// label not present, nothing to do
		return ctrl.Result{}, nil
	}
	ok, err = strconv.ParseBool(inject)
	if err != nil {
		l.Info("Failed to parse label value as boolean", "value", inject)
	}
	if ok {
		l.Info("Injecting Service CA in key `ca.crt`")
		if cm.Data == nil {
			cm.Data = map[string]string{}
		}
		cm.Data["ca.crt"] = r.ServiceCA
		r.Update(ctx, &cm)
	} else {
		l.Info("Label value is `false`, not injecting CA")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *ConfigMapReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.ConfigMap{}).
		Complete(r)
}
