# We sadly need this line due to a bug in the Jenkins Docker Build Step plugin.
FROM scratch

FROM golang:latest as builder
  WORKDIR /go/src/github.com/amsterdam/authz
  COPY . /go/src/github.com/amsterdam/authz
  RUN go get github.com/sparrc/gdm
  RUN gdm restore
  RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o authz .

FROM scratch
  COPY --from=builder /go/src/github.com/amsterdam/authz/authz /authz
  ENTRYPOINT ["/authz"]
