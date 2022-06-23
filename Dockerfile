FROM docker.io/library/alpine:3.16 as runtime

RUN \
  apk add --update --no-cache \
    bash \
    curl \
    ca-certificates \
    tzdata

ENTRYPOINT ["k8s-service-ca-controller"]
COPY k8s-service-ca-controller /usr/bin/

USER 65536:0
