ARG GO_VERSION=1.27

FROM --platform=$BUILDPLATFORM docker.io/library/golang:$GO_VERSION-trixie AS build

ARG TARGETARCH
ARG TARGETOS
# hadolint ignore=DL3008
RUN set -eux; \
    apt-get update; \
    apt-get install --no-install-recommends -y ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile go.mod go.sum ./
RUN make download tool-schemadoc
COPY . .
RUN make build NATIVE_GOOS="$TARGETOS" NATIVE_GOARCH="$TARGETARCH"


FROM scratch

COPY --from=build /src/build/guassp /bin/guassp
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/bin/guassp"]
