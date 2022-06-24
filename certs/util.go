package certs

import "fmt"

var (
	ServiceCertKey = "service.syn.tools/certificate"
)

func CertificateName(svcName string) string {
	return fmt.Sprintf("%s-tls", svcName)
}
