ARG PROXY_CACHE=
ARG GO_IMAGE_REPO=docker.io/library/golang
ARG GO_IMAGE_TAG=1.19

FROM ${PROXY_CACHE}${GO_IMAGE_REPO}:${GO_IMAGE_TAG} AS build

WORKDIR /src/kube-ingress-proxy

COPY main.go go.mod go.sum /src/kube-ingress-proxy/
COPY cmd /src/kube-ingress-proxy/cmd

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -tags netgo -ldflags '-w -extldflags "-static"' -o kube-ingress-proxy main.go

FROM scratch

COPY --from=build /src/kube-ingress-proxy/kube-ingress-proxy /kube-ingress-proxy

EXPOSE 8080

ENTRYPOINT ["/kube-ingress-proxy", "proxy"]
