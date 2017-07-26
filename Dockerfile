FROM golang:latest as builder
  WORKDIR /go/src/github.com/DatapuntAmsterdam/goauth2
  ADD . /go/src/github.com/DatapuntAmsterdam/goauth2
  RUN go get github.com/sparrc/gdm
  RUN gdm restore
  RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o goauth2 .

FROM scratch
  EXPOSE 8080
  COPY --from=builder /go/src/github.com/DatapuntAmsterdam/goauth2/goauth2 /goauth2
  ENTRYPOINT ["/goauth2"]
