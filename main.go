package main

import (
	"time"
)

var (
	// these variables are populated by Goreleaser when releasing
	version = "unknown"
	commit  = "-dirty-"
	date    = time.Now().Format("2006-01-02")

	// TODO: Adjust app name
	appName     = "k8s-service-ca-controller"
	appLongName = "Kubernetes Service CA controller"

	// TODO: Adjust or clear env var prefix
	// envPrefix is the global prefix to use for the keys in environment variables
	envPrefix = "SERVICE_CA_CONTROLLER"
)

func main() {
}
