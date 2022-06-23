package certs

import (
	"context"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func DeleteCertificate(ctx context.Context, l logr.Logger, c client.Client, req ctrl.Request) error {
	certName := CertificateName(req.Name, req.Namespace)

	cert := cmapi.Certificate{}
	if err := c.Get(ctx, client.ObjectKey{Name: certName, Namespace: ServiceNamespace}, &cert); err != nil {
		if errors.IsNotFound(err) {
			// Return if we don't have a Certificate which matches
			// the deleted service
			return nil
		}
		// Bail on other errors
		return err
	}

	l.Info("Cleaning up service certificate and secret")

	// Delete cert
	cert.Name = certName
	cert.Namespace = ServiceNamespace
	if err := c.Delete(ctx, &cert); err != nil {
		return err
	}

	// Delete secret
	secret := &corev1.Secret{}
	secret.Name = certName
	secret.Namespace = ServiceNamespace
	return c.Delete(ctx, secret)
}
