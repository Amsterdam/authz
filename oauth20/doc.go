/*
Package oauth20 provides a fully customizable OAuth 2.0 authorization service
http.handler.

This package currently supports the implicit flow only. Other flows will be
supported in the future. See RFC6749 for more details.

To use oauth20, create a handler and run an HTTP server:

	package main

	import (
		"log"
		"net/http"
		"net/url"

		"github.com/amsterdam/goauth2/oauth20"
	)

	func main() {
		bindAddress := ":8080"
		baseAddress, _ := url.Parse("http://localhost:8080/")
		handler, _ := oauth20.Handler(baseAddress)
		log.Fatal(http.ListenAndServe(bindAddress, handler))
	}


This service creates JSON Web Token (JWS) access tokens signed using the HS256
(HMAC / SHA256) algorithm. To use these tokens in what RFC6749 calls resource
servers you should distribute a shared secret, and verify the token's signature.

When you serve the authorization service bare, as in the above example, it won't
be very useful:

	$ go build
	$ ./test
	2017/09/26 16:05:59 WARN: accesstoken config missing, using random secret.
	2017/09/26 16:05:59 WARN: Using in-memory state storage
	2017/09/26 16:05:59 WARN: using empty scope set
	2017/09/26 16:05:59 WARN: using empty client map
	2017/09/26 16:05:59 WARN: no IdP registered

A minimally useful service provides implementations of:

- oauth20.ClientMap: a registry of clients that are known by the service;
- oauth20.IdP: an identity provider, so users can authenticate;
- oauth20.Authz: the scopes and roles supported by the service;

... and configuration for the accesstokens: the shared secret, the token lifetime and the token issuer identifier.

If you run the service on more than a single node you may also want to use external
state storage such as Redis. To do so, implement the oauth20.StateKeeper interface.

*/
package oauth20
