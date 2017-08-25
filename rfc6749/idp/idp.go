/*
Package idp provides identity provider interfaces and implementations.

This packages serves three purposes:

1. Definitions of the IdP interface and User type.
2. Implementations for specific identity providers.
3. Loading configuration of identity providers and creating instances.

Implementing a new IdP



*/
package idp

import (
	"net/http"
	"net/url"
)

// User wraps all information we want an IdP to return to us.
type User struct {
	UId   string
	Roles []string
}

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns an authentication URL and optional serialized data.
	AuthnRedirect(callbackURL url.URL) (*url.URL, []byte, error)

	// User receives the IdP's callback request and returns a User object or an error.
	User(r *http.Request) (*User, error)
}
