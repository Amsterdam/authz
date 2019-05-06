FROM golang:latest
  ARG https_proxy=http://10.240.2.1:8080/
  ENV https_proxy=$https_proxy
  RUN go get github.com/Amsterdam/authz/jwkgen
  ENTRYPOINT ["jwkgen"]
