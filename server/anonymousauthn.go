package server

import (
	"net/http"
	"net/url"
)

// anonymousIdP
type anonymousIdP struct{}

// anonymousIdP just redirects to the given callback
func (a *anonymousIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// anonymousIdP returns an anonymousUser
func (a *anonymousIdP) User(r *http.Request, state []byte) (*User, error) {
	return &User{"Anonymous", nil}, nil
}
