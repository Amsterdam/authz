package idp

import (
	"net/http"
	"net/url"
)

type AnonymousIdP struct{}

func (a *AnonymousIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// User returns a User and the original opaque token.
func (a *AnonymousIdP) User(r *http.Request) (*User, error) {
	return &User{"Anonymous", []string{}}, nil
}
