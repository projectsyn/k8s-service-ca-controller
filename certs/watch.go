package certs

import (
	"context"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func certIsReady(certconds []cmapi.CertificateCondition) bool {
	for _, c := range certconds {
		if c.Type == cmapi.CertificateConditionReady {
			return c.Status == cmmeta.ConditionTrue
		}
	}
	return false
}

func FetchSecretForService(ctx context.Context, c client.Client, svc *corev1.Service, secret *corev1.Secret) (ctrl.Result, error) {
	cert := cmapi.Certificate{}

	retry := ctrl.Result{
		Requeue:      true,
		RequeueAfter: 5 * time.Second,
	}

	if err := c.Get(ctx, client.ObjectKey{
		Name:      CertificateName(svc.Name, svc.Namespace),
		Namespace: ServiceNamespace,
	}, &cert); err != nil {
		if errors.IsNotFound(err) {
			return retry, nil
		}
		return ctrl.Result{}, err
	}

	if !certIsReady(cert.Status.Conditions) {
		return retry, nil
	}

	secretKey := client.ObjectKey{
		Name:      cert.Spec.SecretName,
		Namespace: ServiceNamespace,
	}
	if err := c.Get(ctx, secretKey, secret); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}
