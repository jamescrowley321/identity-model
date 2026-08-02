# Go Relying-Party conformance harness.
#
# Build context is the repository root (see docker-compose.yml `context: ..`) so
# the module's `replace ../../go` can reach the identity-model/go module.
FROM golang:1.26 AS build
WORKDIR /src
COPY go/ go/
COPY conformance/rp-go/ conformance/rp-go/
WORKDIR /src/conformance/rp-go
RUN CGO_ENABLED=0 go build -trimpath -o /rp-go .

# Static, minimal runtime. The harness trusts the suite cert via SSL_CERT_FILE
# (RootCAs), so no system CA bundle is required.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /rp-go /rp-go
EXPOSE 8888
ENTRYPOINT ["/rp-go"]
