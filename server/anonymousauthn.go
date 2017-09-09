package server

import (
	"net/http"
	"net/url"
)

// anonymousUser
type anonymousUser struct{}

// anonymousUser has UID anonymous
func (u *anonymousUser) UID() string {
	return "anonymous"
}

// anonymousUser has no roles
func (u *anonymousUser) Roles() []string {
	return []string{}
}

// anonymousIdP
type anonymousIdP struct{}

// anonymousIdP just redirects to the given callback
func (a *anonymousIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// anonymousIdP returns an anonymousUser
func (a *anonymousIdP) User(r *http.Request, state []byte) (User, error) {
	return &anonymousUser{}, nil
}
