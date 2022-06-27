package certs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

func TestCerts_CertificateName(t *testing.T) {

	certName := CertificateName("test-svc")
	assert.Equal(t, certName, "test-svc-tls")
}

func TestCerts_isCertReady(t *testing.T) {
}

func makeCert(hasReady, hasIssuing, ready bool) *cmapi.Certificate {
	cert := cmapi.Certificate{
		Status: cmapi.CertificateStatus{
			Conditions: []cmapi.CertificateCondition{},
		},
	}
	readyCond := cmmeta.ConditionFalse
	if ready {
		readyCond = cmmeta.ConditionTrue
	}
	if hasReady {
		cert.Status.Conditions = append(cert.Status.Conditions,
			cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionReady,
				Status: readyCond,
			})
	}
	if hasIssuing {
		cert.Status.Conditions = append(cert.Status.Conditions,
			cmapi.CertificateCondition{
				Type:   cmapi.CertificateConditionIssuing,
				Status: cmmeta.ConditionFalse,
			})
	}

	return &cert
}
