FROM teamserverless/license-check:0.3.6 as license-check

FROM golang:1.13 as build

RUN mkdir -p /go/src/github.com/PEng2020-Subject3/faas-policy-provider/
ENV CGO_ENABLED=0

WORKDIR /go/src/github.com/PEng2020-Subject3/faas-policy-provider

COPY .git     .git
COPY handlers handlers
COPY routing  routing
COPY testing  testing
COPY types    types
COPY vendor   vendor
COPY version  version
COPY main.go  main.go

COPY --from=license-check /license-check /usr/bin/

RUN license-check -path ./ --verbose=false "Alex Ellis" "OpenFaaS Author(s)" "Maximilian Stendler" "Fabian Stiehle" "Florian Weiß"

RUN gofmt -l -d $(find . -type f -name '*.go' -not -path "./vendor/*") \
    && go test $(go list ./... | grep -v /vendor/) -cover \
    && VERSION=$(git describe --all --exact-match `git rev-parse HEAD` | grep tags | sed 's/tags\///') \
    && GIT_COMMIT=$(git rev-list -1 HEAD) \
    && CGO_ENABLED=0 GOOS=linux go build --ldflags "-s -w \
    -X github.com/openfaas/faas-federation/version.GitCommit=${GIT_COMMIT}\
    -X github.com/openfaas/faas-federation/version.Version=${VERSION}" \
    -a -installsuffix cgo -o faas-policy-provider .

# Release stage
FROM alpine:3.12 as ship

LABEL org.label-schema.license="MIT" \
      org.label-schema.vcs-url="https://github.com/PEng2020-Subject3/faas-policy-provider" \
      org.label-schema.vcs-type="Git" \
      org.label-schema.name="openfaas/faas-policy-provider" \
      org.label-schema.vendor="openfaas" \
      org.label-schema.docker.schema-version="1.0"

RUN apk --no-cache add ca-certificates

WORKDIR /root/

EXPOSE 8080

ENV http_proxy      ""
ENV https_proxy     ""

COPY --from=build /go/src/github.com/PEng2020-Subject3/faas-policy-provider/faas-policy-provider    .

CMD ["./faas-policy-provider"]
