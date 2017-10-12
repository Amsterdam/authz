# Authz: OAuth 2.0 authorization service written in Go

[![GoDoc](https://godoc.org/github.com/amsterdam/authz/oauth2?status.svg)](https://godoc.org/github.com/amsterdam/authz/oauth2) [![license](https://img.shields.io/badge/licence-Mozilla%20Public%20Licence%20v2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)

---

## Run

Locally:

```
$ go get github.com/amsterdam/authz
$ authz
$ curl http://localhost:8080/authorize?...
```

Using Docker:

```
$ docker build -t authz .
$ docker run --rm --expose 8080 -p 8080:8080 authz --bind :8080
$ curl http://localhost:8080/authorize?...
```

## Contribute

**Note** We choose to use [gdm](https://github.com/sparrc/gdm) to pin our dependencies so we have reproducible builds. `go get ./...` works just fine so you don't need to use gdm if you don't want to, but if you add dependencies please make sure to update Godeps (`gdm save`).

This is how to grab the sources and install dependencies using gdm:

```
$ mkdir -p $GOPATH/src/github.com/amsterdam/authz
$ cd $GOPATH/src/github.com/amsterdam/authz
$ git clone https://github.com/amsterdam/authz.git
$ go get github.com/sparrc/gdm
$ go get github.com/sirupsen/logrus
$ gdm restore
```
