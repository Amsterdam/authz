FROM golang:latest as builder
  ARG https_proxy=http://10.240.2.1:8080/
  ENV https_proxy=$https_proxy
  WORKDIR /go/src/github.com/amsterdam/authz/tools/swaggerui
  COPY . /go/src/github.com/amsterdam/authz/tools/swaggerui
  RUN go get github.com/sparrc/gdm
  RUN gdm vendor
  RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o oauth2swaggerui .

FROM alpine:latest
  ARG https_proxy=http://10.240.2.1:8080/
  ENV https_proxy=$https_proxy
  COPY --from=builder /go/src/github.com/amsterdam/authz/tools/swaggerui/static /static
  COPY --from=builder /go/src/github.com/amsterdam/authz/tools/swaggerui/oauth2swaggerui /oauth2swaggerui
  ENTRYPOINT ["/oauth2swaggerui"]
