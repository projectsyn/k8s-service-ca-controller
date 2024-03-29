package certs

import (
	"context"
	"fmt"
	"reflect"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// CreateCertificate creates a Certificate resource for an appropriately
// labeled service
func CreateCertificate(ctx context.Context, l logr.Logger, c client.Client, svc corev1.Service, secretName string, scheme *runtime.Scheme) error {
	certName := CertificateName(svc.Name)

	cert := cmapi.Certificate{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      certName,
		Namespace: svc.Namespace,
	}, &cert)
	if err != nil {
		if errors.IsNotFound(err) {
			l.V(1).Info("Certificate resource doesn't exist, creating")
			return newCertificate(ctx, c, certName, secretName, svc, scheme)
		}

		l.V(1).Info("Error looking up certificate resource", "error", err)
		// Unexpected error, bail
		return err
	}

	origCert := cert.DeepCopy()
	err = updateCertificate(&cert, svc, scheme)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(origCert, cert) {
		l.V(1).Info("Applying changes to existing certificate")
		return c.Update(ctx, &cert)
	}
	return nil
}

func newCertificate(ctx context.Context, c client.Client, certName, secretName string, svc corev1.Service, scheme *runtime.Scheme) error {
	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      certName,
			Namespace: svc.Namespace,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: secretName,
			IsCA:       false,
			IssuerRef: cmmeta.ObjectReference{
				Name:  ServiceIssuerName,
				Kind:  "ClusterIssuer",
				Group: "cert-manager.io",
			},
		},
	}

	if err := updateCertificate(cert, svc, scheme); err != nil {
		return err
	}

	return c.Create(ctx, cert)
}

func updateCertificate(cert *cmapi.Certificate, svc corev1.Service, scheme *runtime.Scheme) error {
	svcName := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	svcDNSNames := []string{
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
	cert.Spec.DNSNames = svcDNSNames
	cert.Spec.IPAddresses = svc.Spec.ClusterIPs
	cert.Spec.SecretTemplate = &cmapi.CertificateSecretTemplate{
		Labels: map[string]string{
			ServiceCertSecretLabelKey: cert.Name,
		},
	}

	// Set ownerreference on certificate to service
	controllerutil.SetControllerReference(&svc, cert, scheme)

	return nil
}

func certDurationFromSvc(svc *corev1.Service) (*metav1.Duration, error) {
	// TODO: annotation/label on svc
	d, err := time.ParseDuration("2160h")
	if err != nil {
		return nil, err
	}
	return &metav1.Duration{Duration: d}, nil
}

func certRenewBeforeFromSvc(svc *corev1.Service) (*metav1.Duration, error) {
	// TODO: annotation/label on svc
	d, err := time.ParseDuration("360h")
	if err != nil {
		return nil, err
	}
	return &metav1.Duration{Duration: d}, nil
}
