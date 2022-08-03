package controllers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	extv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectsyn/k8s-service-ca-controller/certs"
)

var (
	cmName              = "test-cm"
	serviceCANamespace  = "service-ca"
	serviceCA_objects   = prepareTestServiceCA(serviceCANamespace)
	unlabeledConfigMap  = prepareConfigMap(cmName, testNs, nil)
	otherLabelConfigMap = prepareConfigMap(cmName, testNs, map[string]string{
		"test": "foo",
	})
	labeledConfigMapTrue = prepareConfigMap(cmName, testNs, map[string]string{
		InjectLabelKey: "true",
	})
	labeledConfigMapFalse = prepareConfigMap(cmName, testNs, map[string]string{
		InjectLabelKey: "false",
	})
	labeledConfigMapInvalid = prepareConfigMap(cmName, testNs, map[string]string{
		InjectLabelKey: "foo",
	})
)

func TestCMController_Reconcile(t *testing.T) {
	ctx := context.Background()
	tests := map[string]struct {
		objects      []client.Object
		err          error
		res          ctrl.Result
		expectedData string
	}{
		"UnlabeledCM": {
			objects: []client.Object{
				&unlabeledConfigMap,
			},
			err:          nil,
			res:          ctrl.Result{},
			expectedData: "",
		},
		"CM_OtherLabels": {
			objects: []client.Object{
				&otherLabelConfigMap,
			},
			err:          nil,
			res:          ctrl.Result{},
			expectedData: "",
		},
		"LabeledCMFalse": {
			objects: []client.Object{
				&labeledConfigMapFalse,
			},
			err:          nil,
			res:          ctrl.Result{},
			expectedData: "",
		},
		"LabeledCMInvalid": {
			objects: []client.Object{
				&labeledConfigMapInvalid,
			},
			err:          nil,
			res:          ctrl.Result{},
			expectedData: "",
		},
		"LabeledCMTrue": {
			objects: []client.Object{
				&labeledConfigMapTrue,
			},
			err:          nil,
			res:          ctrl.Result{},
			expectedData: "TEST_CA",
		},
	}

	for _, tc := range tests {
		objs := append(tc.objects, serviceCA_objects...)
		c, scheme := prepareTest(t, objs)
		r := ConfigMapReconciler{
			Client:      c,
			Scheme:      scheme,
			CANamespace: serviceCANamespace,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: testNs,
				Name:      cmName,
			},
		})
		assert.Equal(t, tc.err, err)
		assert.Equal(t, tc.res, res)

		if tc.expectedData != "" {
			cm := corev1.ConfigMap{}
			err := c.Get(ctx, client.ObjectKeyFromObject(tc.objects[0]), &cm)
			require.NoError(t, err)
			ca, ok := cm.Data["ca.crt"]
			assert.True(t, ok)
			assert.Equal(t, ca, tc.expectedData)
		}
	}
}

func prepareConfigMap(name, namespace string, labels map[string]string) corev1.ConfigMap {
	return corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
	}
}

func prepareTestServiceCA(testCANamespace string) []client.Object {
	return []client.Object{
		&extv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name: "certificates.cert-manager.io",
			},
		},
		&cmapi.Issuer{
			ObjectMeta: metav1.ObjectMeta{
				Name:      certs.SelfSignedIssuerName,
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
				Name:      certs.CACertName,
				Namespace: testCANamespace,
			},
			Spec: cmapi.CertificateSpec{
				SecretName: certs.CASecretName,
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
				Name:      certs.CASecretName,
				Namespace: testCANamespace,
			},
			Data: map[string][]byte{
				"tls.crt": []byte("TEST_CA"),
			},
		},
	}
}
