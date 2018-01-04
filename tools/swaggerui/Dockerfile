FROM golang:latest as builder
  WORKDIR /go/src/github.com/amsterdam/authz/tools/swaggerui
  COPY . /go/src/github.com/amsterdam/authz/tools/swaggerui
  RUN go get github.com/sparrc/gdm
  RUN gdm vendor
  RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o oauth2swaggerui .

FROM alpine:latest
  COPY --from=builder /go/src/github.com/amsterdam/authz/tools/swaggerui/oauth2swaggerui /oauth2swaggerui
  ENTRYPOINT ["/oauth2swaggerui"]
