package certs

import (
	"context"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
						Name:      SelfSignedIssuerName,
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
			Name:      SelfSignedIssuerName,
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
						Name:      CACertName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.CertificateSpec{
						CommonName: CAName,
						IsCA:       true,
						SecretName: CASecretName,
						PrivateKey: &cmapi.CertificatePrivateKey{
							Algorithm: cmapi.ECDSAKeyAlgorithm,
							Size:      521,
						},
						IssuerRef: cmmeta.ObjectReference{
							Name:  SelfSignedIssuerName,
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
			Name:      CACertName,
			Namespace: testCANamespace,
		}, &cert)
		assert.NoError(t, err)
		assert.Equal(t, cert.Spec.IsCA, true)
		assert.Equal(t, cert.Spec.CommonName, CAName)
		assert.Equal(t, cert.Spec.SecretName, CASecretName)
		assert.Equal(t, cert.Spec.PrivateKey, &cmapi.CertificatePrivateKey{
			Algorithm: cmapi.ECDSAKeyAlgorithm,
			Size:      521,
		})
		assert.Equal(t, cert.Spec.IssuerRef, cmmeta.ObjectReference{
			Name:  SelfSignedIssuerName,
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
						Name: ServiceIssuerName,
					},
					Spec: cmapi.IssuerSpec{
						IssuerConfig: cmapi.IssuerConfig{
							CA: &cmapi.CAIssuer{
								SecretName: CASecretName,
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
			Name: ServiceIssuerName,
		}, &iss)
		assert.NoError(t, err)
		assert.Equal(t, &cmapi.CAIssuer{
			SecretName: CASecretName,
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
		"CRDMissing": {
			objects:  []client.Object{},
			errcheck: apierrors.IsNotFound,
			ca:       "",
		},
		"CACertReady": {
			objects: []client.Object{
				&extv1.CustomResourceDefinition{
					ObjectMeta: metav1.ObjectMeta{
						Name: "certificates.cert-manager.io",
					},
				},
				&cmapi.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      SelfSignedIssuerName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.IssuerSpec{
						IssuerConfig: cmapi.IssuerConfig{
							SelfSigned: &cmapi.SelfSignedIssuer{},
						},
					},
				},
				&cmapi.Certificate{
					ObjectMeta: metav1.ObjectMeta{
						Name:      CACertName,
						Namespace: testCANamespace,
					},
					Spec: cmapi.CertificateSpec{
						SecretName: CASecretName,
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
						Name:      CASecretName,
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

	for testn, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})

		ca, err := GetServiceCA(ctx, c, l, testCANamespace)
		assert.True(t, tc.errcheck(err), testn)
		if err == nil {
			assert.Equal(t, tc.ca, ca)
		}
	}
}
