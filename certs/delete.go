package certs

import (
	"context"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func DeleteSecret(ctx context.Context, l logr.Logger, c client.Client, req ctrl.Request) error {
	secrets := corev1.SecretList{}
	err := c.List(ctx, &secrets,
		client.MatchingLabels{
			ServiceCertKey: CertificateName(req.Name),
		}, client.InNamespace(req.Namespace))
	if err != nil {
		return err
	}
	for _, secret := range secrets.Items {
		l.Info("deleting secret", "secret", secret.Name)
		err = c.Delete(ctx, &secret)
		if err != nil && !errors.IsNotFound(err) {
			return err
		}
	}

	return nil
}
