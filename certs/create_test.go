package certs

import (
	"context"
	"fmt"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCerts_CreateCertificate(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)

	tests := map[string]struct {
		svc        corev1.Service
		secretName string
		err        error
		objects    []client.Object
	}{
		"Create_NoError": {
			svc:        prepareService("test-svc", "test-ns"),
			secretName: "foo-tls",
			err:        nil,
			objects:    []client.Object{},
		},
		"Update_NoError": {
			svc:        prepareService("test-svc-2", "test-ns"),
			secretName: "foo-tls",
			err:        nil,
			objects: []client.Object{
				prepareCertificate("test-svc", "test-ns", "foo-tls"),
			},
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})
		err := CreateCertificate(ctx, l, c, tc.svc, tc.secretName)
		assert.Equal(t, tc.err, err)
		if err == nil {
			verifyCertificate(t, ctx, c, fmt.Sprintf("%s-tls", tc.svc.Name), tc.secretName, &tc.svc)
		}
	}
}

func TestCerts_newCertificate(t *testing.T) {
	ctx := context.Background()
	c := prepareTest(t, testCfg{initObjs: []client.Object{}})

	tests := map[string]struct {
		certName   string
		secretName string
		svc        corev1.Service
		err        error
	}{
		"StandardCertificate": {
			certName:   "test-cert",
			secretName: "test-cert-tls",
			svc:        prepareService("test-svc", "test-ns"),
		},
	}

	for _, tc := range tests {
		err := newCertificate(ctx, c, tc.certName, tc.secretName, tc.svc)
		assert.Equal(t, tc.err, err)
		if err == nil {
			verifyCertificate(t, ctx, c, tc.certName, tc.secretName, &tc.svc)
		}
	}
}

func TestCerts_updateCertificate(t *testing.T) {
	cert := cmapi.Certificate{}
	cert.Name = "test-cert"
	svc := prepareService("test-svc", "test-ns")
	err := updateCertificate(&cert, svc)

	assert.ErrorIs(t, err, nil)
	assert.Equal(t, dnsNames(&svc), cert.Spec.DNSNames)
	assert.Equal(t, []string{
		"198.51.100.10",
	}, cert.Spec.IPAddresses)
	assert.Equal(t, &metav1.Duration{Duration: time.Hour * 2160}, cert.Spec.Duration)
	assert.Equal(t, &metav1.Duration{Duration: time.Hour * 360}, cert.Spec.RenewBefore)
	assert.Equal(t, map[string]string{
		ServiceCertKey: "test-cert",
	}, cert.Spec.SecretTemplate.Labels)
}

func TestCerts_certDurationFromSvc(t *testing.T) {
	tests := map[string]struct {
		svc corev1.Service
		d   metav1.Duration
		err error
	}{
		"ParseSuccess": {
			svc: prepareService("test-svc", "test-ns"),
			d:   prepareDuration(2160 * time.Hour),
			err: nil,
		},
	}

	for _, tc := range tests {
		d, err := certDurationFromSvc(&tc.svc)
		assert.Equal(t, &tc.d, d)
		assert.Equal(t, tc.err, err)
	}
}

func TestCerts_certRenewBeforeFromSvc(t *testing.T) {
	tests := map[string]struct {
		svc corev1.Service
		d   metav1.Duration
		err error
	}{
		"ParseSuccess": {
			svc: prepareService("test-svc", "test-ns"),
			d:   prepareDuration(360 * time.Hour),
			err: nil,
		},
	}

	for _, tc := range tests {
		d, err := certRenewBeforeFromSvc(&tc.svc)
		assert.Equal(t, &tc.d, d)
		assert.Equal(t, tc.err, err)
	}
}

func verifyCertificate(t *testing.T, ctx context.Context, c client.Client, certName, secretName string, svc *corev1.Service) {
	cert := cmapi.Certificate{}
	err := c.Get(ctx, client.ObjectKey{
		Name:      certName,
		Namespace: svc.Namespace,
	}, &cert)
	assert.NoError(t, err)
	assert.Equal(t, secretName, cert.Spec.SecretName)
	assert.Equal(t, dnsNames(svc), cert.Spec.DNSNames)
	assert.Equal(t, svc.Spec.ClusterIPs, cert.Spec.IPAddresses)
	assert.Equal(t, &metav1.Duration{Duration: 2160 * time.Hour}, cert.Spec.Duration)
	assert.Equal(t, &metav1.Duration{Duration: 360 * time.Hour}, cert.Spec.RenewBefore)
}

func dnsNames(svc *corev1.Service) []string {
	svcNameNs := fmt.Sprintf("%s.%s", svc.Name, svc.Namespace)
	return []string{
		svc.Name,
		svcNameNs,
		fmt.Sprintf("%s.svc", svcNameNs),
		fmt.Sprintf("%s.svc.cluster.local", svcNameNs),
	}
}

func prepareService(name, namespace string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{
				"198.51.100.10",
			},
		},
	}
}

func prepareCertificate(name, namespace, secretName string) *cmapi.Certificate {
	return &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("%s-tls", name),
			Namespace: namespace,
		},
		Spec: cmapi.CertificateSpec{
			SecretName: secretName,
		},
	}
}

func prepareDuration(d time.Duration) metav1.Duration {
	return metav1.Duration{Duration: d}
}

type testCfg struct {
	initObjs []client.Object
}

func prepareTest(t *testing.T, cfg testCfg) client.Client {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(cfg.initObjs...).
		Build()

	return client
}
