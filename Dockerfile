# We sadly need this line due to a bug in the Jenkins Docker Build Step plugin.
FROM scratch

FROM golang:latest as builder
  WORKDIR /go/src/github.com/amsterdam/goauth2
  COPY . /go/src/github.com/amsterdam/goauth2
  RUN go get github.com/sparrc/gdm
  RUN gdm restore
  RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o goauth2 .

FROM scratch
  COPY --from=builder /go/src/github.com/amsterdam/goauth2/goauth2 /goauth2
  ENTRYPOINT ["/goauth2"]
