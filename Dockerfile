FROM golang:latest
  ARG https_proxy=http://10.240.2.1:8080/
  ENV https_proxy=$https_proxy
  WORKDIR /go/src/github.com/amsterdam/authz
  COPY . /go/src/github.com/amsterdam/authz
  RUN go get github.com/sparrc/gdm
  RUN gdm restore
  RUN go install
  ENTRYPOINT ["authz"]
