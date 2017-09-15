package servertest

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/server"
)

// A mock authorization provider
type Authz map[string][]Role

type Role string

func (a Authz) ValidScope(scope ...string) bool {
	for _, s := range scope {
		if _, ok := a[s]; !ok {
			return false
		}
	}
	return true
}

// Create scopeset for the user's given roles
func (a Authz) ScopeSetFor(u *server.User) server.ScopeSet {
	s := make(Authz)
	for _, r := range u.Roles {
		for scope, roles := range a {
			for _, role := range roles {
				if r == string(role) {
					s[scope] = nil
				}
			}
		}
	}
	return s
}

// A mock authentication provider
type Authn []*server.User

// Authnredirect sets a User under a randomly created byte slice
func (a Authn) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// User returns the previously set user
func (a Authn) User(r *http.Request, state []byte) (*server.User, error) {
	if uid, ok := r.URL.Query()["uid"]; !ok {
		return nil, errors.New("Unknown uid")
	} else {
		for _, u := range a {
			if u.UID == uid[0] {
				return u, nil
			}
		}
	}
	return nil, errors.New("Invalid state")
}

// Mock client map
type ClientMap []*server.Client

func (m ClientMap) Get(id string) (*server.Client, error) {
	for _, c := range m {
		if c.Id == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}
