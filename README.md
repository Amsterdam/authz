# GOAuth 2.0: OAuth 2.0 authorization service written in Go

[![GoDoc](https://godoc.org/github.com/DatapuntAmsterdam/goauth2?status.svg)](https://godoc.org/github.com/DatapuntAmsterdam/goauth2) [![license](https://img.shields.io/badge/licence-Mozilla%20Public%20Licence%20v2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)

---

## Run

Locally:

```
$ go get github.com/DatapuntAmsterdam/goauth2
$ ./goauth2
```

Using Docker:

```
$ docker build -t goauth2 .
$ docker run goauth2 --help
```

## Contribute

We use https://github.com/sparrc/gdm for dependency management.

This is how to grab the sources and install dependencies:

```
$ mkdir -p $GOPATH/src/github.com/DatapuntAmsterdam/goauth2
$ cd $GOPATH/src/github.com/DatapuntAmsterdam/goauth2
$ git clone https://github.com/DatapuntAmsterdam/goauth2.git
$ go get github.com/sparrc/gdm
$ gdm restore
```
