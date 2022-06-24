package certs

import (
	"fmt"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
)

var (
	ServiceCertKey = "service.syn.tools/certificate"
)

func CertificateName(svcName string) string {
	return fmt.Sprintf("%s-tls", svcName)
}

func isCertReady(cert *cmapi.Certificate) bool {
	for _, c := range cert.Status.Conditions {
		if c.Type == cmapi.CertificateConditionReady {
			return c.Status == cmmeta.ConditionTrue
		}
	}
	return false
}
