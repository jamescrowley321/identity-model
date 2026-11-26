# Go RP conformance harness (conformance/go/), built against the Go library in
# go/ through the harness module's replace directive. Build context: repo root.
FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build

WORKDIR /src
# Module files first so the dependency download is cached across source edits.
COPY go/go.mod go/go.sum go/
COPY conformance/go/go.mod conformance/go/go.sum conformance/go/
RUN cd conformance/go && go mod download

COPY go/ go/
COPY conformance/go/ conformance/go/
# The harness unit tests (fake OP, every reason class) gate the image, so the
# conformance job runs them on every build.
RUN cd conformance/go && CGO_ENABLED=0 go vet ./... && CGO_ENABLED=0 go test ./...
RUN cd conformance/go && CGO_ENABLED=0 go build -trimpath -o /out/conformance-rp-go .

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

COPY --from=build /out/conformance-rp-go /usr/local/bin/conformance-rp-go

EXPOSE 8890

ENTRYPOINT ["conformance-rp-go"]
