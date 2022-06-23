package certs

import "fmt"

var (
	ServiceNamespace = "service-ca"
)

func CertificateName(svcName, svcNamespace string) string {
	return fmt.Sprintf("%s-%s-tls", svcNamespace, svcName)
}
