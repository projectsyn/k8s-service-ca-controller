package certs

import (
	"context"
	"testing"

	"github.com/go-logr/logr/testr"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestCerts_DeleteSecret(t *testing.T) {
	ctx := context.Background()
	l := testr.New(t)
	tests := map[string]struct {
		svcName      string
		svcNamespace string
		objects      []client.Object
		err          error
	}{
		"NoMatchingSecret": {
			svcName:      "test-svc",
			svcNamespace: "test-ns",
			objects: []client.Object{
				&corev1.Secret{},
			},
			err: nil,
		},
		"DeleteSecret": {
			objects: []client.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-secret",
						Namespace: "test-ns",
						Labels: map[string]string{
							ServiceCertKey: "test-svc-tls",
						},
					},
				},
			},
			err: nil,
		},
	}

	for _, tc := range tests {
		c := prepareTest(t, testCfg{
			initObjs: tc.objects,
		})
		err := DeleteSecret(ctx, l, c, ctrl.Request{
			NamespacedName: client.ObjectKey{
				Name:      tc.svcName,
				Namespace: tc.svcNamespace,
			},
		})
		assert.Equal(t, err, tc.err)
	}
}
