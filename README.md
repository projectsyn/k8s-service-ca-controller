# Kubernetes Service CA controller

[![Build](https://img.shields.io/github/workflow/status/projectsyn/k8s-service-ca-controller/Test)][build]
![Go version](https://img.shields.io/github/go-mod/go-version/projectsyn/k8s-service-ca-controller)
[![Version](https://img.shields.io/github/v/release/projectsyn/k8s-service-ca-controller)][releases]
[![Maintainability](https://img.shields.io/codeclimate/maintainability/projectsyn/k8s-service-ca-controller)][codeclimate]
[![Coverage](https://img.shields.io/codeclimate/coverage/projectsyn/k8s-service-ca-controller)][codeclimate]
[![GitHub downloads](https://img.shields.io/github/downloads/projectsyn/k8s-service-ca-controller/total)][releases]

[build]: https://github.com/projectsyn/k8s-service-ca-controller/actions?query=workflow%3ATest
[releases]: https://github.com/projectsyn/k8s-service-ca-controller/releases
[codeclimate]: https://codeclimate.com/github/projectsyn/k8s-service-ca-controller

The Kubernetes Service CA controller issues certificates for Services labelled with `service.syn.tools/serving-cert-secret-name`.
The controller uses [cert-manager] for the actual certificate issuing and copies the generated certificate secret into the service namespace.
