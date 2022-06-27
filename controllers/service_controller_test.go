package controllers

import (
	"context"
	"testing"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var (
	testNs            = "default"
	unlabeledService  = prepareService("test-svc", testNs, nil)
	otherLabelService = prepareService("test-svc", testNs, map[string]string{
		"test": "foo",
	})
	labeledService = prepareService("test-svc", testNs, map[string]string{
		ServingCertLabelKey: "foo-tls",
	})
)

func TestSvcController_Reconcile(t *testing.T) {
	ctx := context.Background()
	tests := map[string]struct {
		objects         []client.Object
		err             error
		res             ctrl.Result
		expectedCertKey *client.ObjectKey
	}{
		"UnlabeledService": {
			objects: []client.Object{
				&unlabeledService,
			},
			err:             nil,
			res:             ctrl.Result{},
			expectedCertKey: nil,
		},
		"Service_OtherLabels": {
			objects: []client.Object{
				&otherLabelService,
			},
			err:             nil,
			res:             ctrl.Result{},
			expectedCertKey: nil,
		},
		"LabeledService": {
			objects: []client.Object{
				&labeledService,
			},
			err: nil,
			res: ctrl.Result{},
			expectedCertKey: &client.ObjectKey{
				Name:      "test-svc-tls",
				Namespace: testNs,
			},
		},
	}

	for _, tc := range tests {
		c, scheme := prepareTest(t, tc.objects)
		r := ServiceReconciler{
			Client: c,
			Scheme: scheme,
		}
		res, err := r.Reconcile(ctx, ctrl.Request{
			NamespacedName: client.ObjectKey{
				Namespace: testNs,
				Name:      "test-svc",
			},
		})
		assert.Equal(t, tc.err, err)
		assert.Equal(t, tc.res, res)

		if tc.expectedCertKey != nil {
			cert := cmapi.Certificate{}
			err = c.Get(ctx, *tc.expectedCertKey, &cert)
			require.NoError(t, err)
			assert.Equal(t, cert.Spec.SecretName,
				labeledService.Labels[ServingCertLabelKey])
		}
	}
}

func prepareTest(t *testing.T, initObjs []client.Object) (client.Client, *runtime.Scheme) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(initObjs...).
		Build()

	return client, scheme
}

func prepareService(name, namespace string, labels map[string]string) corev1.Service {
	return corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIPs: []string{
				"198.51.100.10",
			},
		},
	}
}
