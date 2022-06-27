package certs

import (
	"context"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	testCANamespace = "cert-manager"
)

func TestCerts_ensureSelfSignedIssuer(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)

	tests := map[string]struct {
		objects []client.Object
	}{
		"CreateIssuer": {
			objects: []client.Object{},
		},
		"IssuerExists": {
			objects: []client.Object{
				&cmapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      selfSignedIssuerName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.IssuerSpec{
						IssuerConfig: cmapi.IssuerConfig{
							SelfSigned: &cmapi.SelfSignedIssuer{},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})
		err := ensureSelfSignedIssuer(ctx, c, l, testCANamespace)
		assert.NoError(t, err)
		iss := cmapi.Issuer{}
		err = c.Get(ctx, client.ObjectKey{
			Name:      selfSignedIssuerName,
			Namespace: testCANamespace,
		}, &iss)
		assert.NoError(t, err)
		assert.Equal(t, &cmapi.SelfSignedIssuer{}, iss.Spec.SelfSigned)
	}
}

func TestCerts_ensureCACertificate(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)

	tests := map[string]struct {
		objects []client.Object
	}{
		"CreateCACertificate": {
			objects: []client.Object{},
		},
		"CACertificateExists": {
			objects: []client.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      caCertName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.CertificateSpec{
						CommonName: caName,
						IsCA:       true,
						SecretName: caSecretName,
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      521,
						},
						IssuerRef: cmmeta.ObjectReference{
							Name:  selfSignedIssuerName,
							Kind:  "Issuer",
							Group: "cert-manager.io",
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})
		err := ensureCACertificate(ctx, c, l, testCANamespace)
		assert.NoError(t, err)
		cert := cmapi.Certificate{}
		err = c.Get(ctx, client.ObjectKey{
			Name:      caCertName,
			Namespace: testCANamespace,
		}, &cert)
		assert.NoError(t, err)
		assert.Equal(t, cert.Spec.IsCA, true)
		assert.Equal(t, cert.Spec.CommonName, caName)
		assert.Equal(t, cert.Spec.SecretName, caSecretName)
		assert.Equal(t, cert.Spec.PrivateKey, &cmapi.CertificatePrivateKey{
			Algorithm: cmapi.ECDSAKeyAlgorithm,
			Size:      521,
		})
		assert.Equal(t, cert.Spec.IssuerRef, cmmeta.ObjectReference{
			Name:  selfSignedIssuerName,
			Kind:  "Issuer",
			Group: "cert-manager.io",
		})
	}
}

func TestCerts_ensureSeviceCAIssuer(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)

	tests := map[string]struct {
		objects []client.Object
	}{
		"CreateIssuer": {
			objects: []client.Object{},
		},
		"IssuerExists": {
			objects: []client.Object{
				&cmapi.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: serviceIssuerName,
					},
					Spec: cmapi.IssuerSpec{
						IssuerConfig: cmapi.IssuerConfig{
							CA: &cmapi.CAIssuer{
								SecretName: caSecretName,
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})
		err := ensureServiceCAIssuer(ctx, c, l, testCANamespace)
		assert.NoError(t, err)
		iss := cmapi.ClusterIssuer{}
		err = c.Get(ctx, client.ObjectKey{
			Name: serviceIssuerName,
		}, &iss)
		assert.NoError(t, err)
		assert.Equal(t, &cmapi.CAIssuer{
			SecretName: caSecretName,
		}, iss.Spec.CA)
	}
}

func TestCerts_GetServiceCA(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)

	tests := map[string]struct {
		objects  []client.Object
		errcheck func(error) bool
		ca       string
	}{
		"CACertMissing": {
			objects:  []client.Object{},
			errcheck: apierrors.IsNotFound,
			ca:       "",
		},
		"CACertFound": {
			objects: []client.Object{
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      caCertName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.CertificateSpec{
						SecretName: caSecretName,
					},
					Status: cmapi.CertificateStatus{
						Conditions: []cmapi.CertificateCondition{
							{
								Type:   cmapi.CertificateConditionReady,
								Status: cmmeta.ConditionTrue,
							},
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      caSecretName,
						Namespace: testCANamespace,
					},
					Data: map[string][]byte{
						"tls.crt": []byte("TEST_CA"),
					},
				},
			},
			errcheck: func(err error) bool { return err == nil },
			ca:       "TEST_CA",
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})

		ca, err := GetServiceCA(ctx, c, l, testCANamespace)
		assert.True(t, tc.errcheck(err))
		if err == nil {
			assert.Equal(t, tc.ca, ca)
		}
	}
}
