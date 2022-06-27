package certs

import (
	"context"
	"fmt"
	"time"
	"unicode/utf8"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	selfSignedIssuerName = "service-ca-self-signed"
	caCertName           = "service-ca-certificate"
	caName               = "service-ca"
	caSecretName         = "service-ca-root"
	serviceIssuerName    = "service-ca-issuer"
)

// EnsureCA ensures that the Service CA is completely setup on the cluster
func EnsureCA(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) error {
	log := l.WithValues("caNamespace", caNamespace)

	err := ensureSelfSignedIssuer(ctx, c, log, caNamespace)
	if err != nil {
		return err
	}

	err = ensureCACertificate(ctx, c, log, caNamespace)
	if err != nil {
		return err
	}

	err = ensureServiceCAIssuer(ctx, c, log, caNamespace)
	if err != nil {
		return err
	}

	return nil
}

// ensureSelfSignedIssuer creates a self-signed issuer in `caNamespace` if it
// doesn't exist
func ensureSelfSignedIssuer(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) error {
	iss := cmapi.Issuer{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      selfSignedIssuerName,
		Namespace: caNamespace,
	}, &iss)
	if err != nil && !errors.IsNotFound(err) {
		l.Error(err, "while fetching self-signed issuer")
		return err
	}
	if errors.IsNotFound(err) {
		l.Info("Self-signed issuer doesn't exist, creating...")
		iss.Name = selfSignedIssuerName
		iss.Namespace = caNamespace
		iss.Spec.SelfSigned = &cmapi.SelfSignedIssuer{}
		if err := c.Create(ctx, &iss); err != nil {
			return err
		}
	}
	return nil
}

// ensureCACertificate creates the Service CA certificate if it doesn't exist
func ensureCACertificate(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) error {
	// Create CA cert if not exists (in caNamespace)
	caCert := cmapi.Certificate{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      caCertName,
		Namespace: caNamespace,
	}, &caCert)
	if err != nil && !errors.IsNotFound(err) {
		l.Error(err, "while fetching service CA certificate")
		return err
	}
	if errors.IsNotFound(err) {
		l.Info("Service CA certificate doesn't exist, creating...")
		initCACertificate(&caCert, caNamespace)
		if err := c.Create(ctx, &caCert); err != nil {
			return err
		}
	}
	return nil
}

// ensureServiceCAIssuer creates the ClusterIssuer for the Service CA if it
// doesn't exist
func ensureServiceCAIssuer(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) error {
	// Create Service CA clusterissuer, if not exists
	serviceIssuer := cmapi.ClusterIssuer{}
	err := c.Get(ctx, client.ObjectKey{Name: serviceIssuerName}, &serviceIssuer)
	if err != nil && !errors.IsNotFound(err) {
		l.Error(err, "while fetching service CA cluster issuer")
		return err
	}
	if errors.IsNotFound(err) {
		l.Info("Service CA cluster issuer doesn't exist, creating...")
		serviceIssuer.Name = serviceIssuerName
		serviceIssuer.Spec.CA = &cmapi.CAIssuer{
			SecretName: caSecretName,
		}
		if err := c.Create(ctx, &serviceIssuer); err != nil {
			return err
		}
	}
	return nil
}

// initCACertificate initializes the Service CA certificate resource
func initCACertificate(caCert *cmapi.Certificate, caNamespace string) {
	caCert.Name = caCertName
	caCert.Namespace = caNamespace
	caCert.Spec.IsCA = true
	caCert.Spec.CommonName = caName
	caCert.Spec.SecretName = caSecretName
	// TODO: make the private key config configurable?
	caCert.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
		Algorithm: cmapi.ECDSAKeyAlgorithm,
		Size:      521,
	}
	caCert.Spec.IssuerRef = cmmeta.ObjectReference{
		Name:  selfSignedIssuerName,
		Kind:  "Issuer",
		Group: "cert-manager.io",
	}
}

// GetServiceCA returns the Service CA certificate as a string
func GetServiceCA(ctx context.Context, c client.Client, l logr.Logger, caNamespace string) (string, error) {
	log := l.WithValues("caNamespace", caNamespace)
	caCert := cmapi.Certificate{}
	for {
		err := c.Get(ctx, client.ObjectKey{
			Name:      caCertName,
			Namespace: caNamespace,
		}, &caCert)
		if err != nil {
			log.Error(err, "fetching CA certificate")
			return "", err
		}

		if isCertReady(&caCert) {
			// break loop if certificate is ready
			break
		}
		log.Info("CA certificate not yet ready")
		time.Sleep(time.Second)
	}

	secret := corev1.Secret{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      caCert.Spec.SecretName,
		Namespace: caNamespace,
	}, &secret)
	if err != nil {
		log.Error(err, "Fetching CA secret")
		return "", err
	}
	caBytes, ok := secret.Data["tls.crt"]
	if !ok {
		return "", fmt.Errorf("key `tls.crt` missing in CA secret")
	}

	if !utf8.Valid(caBytes) {
		return "", fmt.Errorf("`tls.crt` in secret is not valid UTF-8")
	}

	return string(caBytes), nil
}
