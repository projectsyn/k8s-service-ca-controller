package certs

import (
	"context"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	SelfSignedIssuerName = "service-ca-self-signed"
	CACertName           = "service-ca-certificate"
	CAName               = "service-ca"
	CASecretName         = "service-ca-root"
	ServiceIssuerName    = "service-ca-issuer"
)

func EnsureCA(c client.Client, l logr.Logger, caNamespace string) error {
	log := l.WithValues("caNamespace", caNamespace)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create self-signed issuer if not exists (in caNamespace)
	iss := cmapi.Issuer{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      SelfSignedIssuerName,
		Namespace: caNamespace,
	}, &iss)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "while fetching self-signed issuer")
		return err
	}
	if errors.IsNotFound(err) {
		log.Info("Self-signed issuer doesn't exist, creating...")
		iss.Name = SelfSignedIssuerName
		iss.Namespace = caNamespace
		iss.Spec.SelfSigned = &cmapi.SelfSignedIssuer{}
		if err := c.Create(ctx, &iss); err != nil {
			return err
		}
	}

	// Create CA cert if not exists (in caNamespace)
	caCert := cmapi.Certificate{}
	err = c.Get(ctx, client.ObjectKey{
		Name:      CACertName,
		Namespace: caNamespace,
	}, &caCert)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "while fetching service CA certificate")
		return err
	}
	if errors.IsNotFound(err) {
		log.Info("Service CA certificate doesn't exist, creating...")
		initCACertificate(&caCert, caNamespace)
		if err := c.Create(ctx, &caCert); err != nil {
			return err
		}
	}

	// Create Service CA clusterissuer, if not exists
	serviceIssuer := cmapi.ClusterIssuer{}
	err = c.Get(ctx, client.ObjectKey{Name: ServiceIssuerName}, &serviceIssuer)
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "while fetching service CA cluster issuer")
		return err
	}
	if errors.IsNotFound(err) {
		log.Info("Service CA cluster issuer doesn't exist, creating...")
		serviceIssuer.Name = ServiceIssuerName
		serviceIssuer.Spec.CA = &cmapi.CAIssuer{
			SecretName: CASecretName,
		}
		if err := c.Create(ctx, &serviceIssuer); err != nil {
			return err
		}
	}

	return nil
}

func initCACertificate(caCert *cmapi.Certificate, caNamespace string) {
	caCert.Name = CACertName
	caCert.Namespace = caNamespace
	caCert.Spec.IsCA = true
	caCert.Spec.CommonName = CAName
	caCert.Spec.SecretName = CASecretName
	// TODO: make the private key config configurable?
	caCert.Spec.PrivateKey = &cmapi.CertificatePrivateKey{
		Algorithm: cmapi.ECDSAKeyAlgorithm,
		Size:      521,
	}
	caCert.Spec.IssuerRef = cmmeta.ObjectReference{
		Name:  SelfSignedIssuerName,
		Kind:  "Issuer",
		Group: "",
	}
}
