package certs

import (
	"context"
	"fmt"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CreateCertificate(ctx context.Context, l logr.Logger, c client.Client, svc corev1.Service) error {
	certName := CertificateName(svc.Name, svc.Namespace)

	cert := cmapi.Certificate{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      certName,
		Namespace: "service-ca",
	}, &cert)
	if err != nil {
		if errors.IsNotFound(err) {
			l.Info("Certificate resource doesn't exist, creating")
			return newCertificate(ctx, c, certName, svc)
		}

		l.Info("Error looking up certificate resource", "error", err)
		// Unexpected error, bail
		return err
	}

	l.Info("Found existing Certificate, updating...")

	err = updateCertificate(&cert, svc)
	if err != nil {
		return err
	}

	return c.Update(ctx, &cert)
}

func newCertificate(ctx context.Context, c client.Client, certName string, svc corev1.Service) error {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: "service-ca", // TODO: make configurable
		},
		Spec: cmapi.CertificateSpec{
			SecretName: certName,
			IsCA:       false,
			IssuerRef: cmmeta.ObjectReference{
				Name:  "service-issuer",
				Kind:  "Issuer",
				Group: "cert-manager.io",
			},
		},
	}

	if err := updateCertificate(cert, svc); err != nil {
		return err
	}

	return c.Create(ctx, cert)
}

func updateCertificate(cert *cmapi.Certificate, svc corev1.Service) error {
	svcName := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	svcDnsNames := []string{
		svc.Name,
		svcName,
		fmt.Sprintf("%s.svc", svcName),
		fmt.Sprintf("%s.svc.cluster.local", svcName),
	}

	certDuration, err := certDurationFromSvc(&svc)
	if err != nil {
		return fmt.Errorf("Error parsing certificate duration from service: %v", err)
	}
	certRenewBefore, err := certRenewBeforeFromSvc(&svc)
	if err != nil {
		return fmt.Errorf("Error parsing certificate renew-before from service: %v", err)
	}

	cert.Spec.Duration = certDuration
	cert.Spec.RenewBefore = certRenewBefore
	cert.Spec.DNSNames = svcDnsNames
	cert.Spec.IPAddresses = svc.Spec.ClusterIPs

	return nil
}

func certDurationFromSvc(svc *corev1.Service) (*metav1.Duration, error) {
	// TODO: annotation/label on svc?
	d, err := time.ParseDuration("2160h")
	if err != nil {
		return nil, err
	}
	return &metav1.Duration{Duration: d}, nil
}

func certRenewBeforeFromSvc(svc *corev1.Service) (*metav1.Duration, error) {
	// TODO: annotation/label on svc?
	d, err := time.ParseDuration("360h")
	if err != nil {
		return nil, err
	}
	return &metav1.Duration{Duration: d}, nil
}
