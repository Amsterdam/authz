package server

import (
	"errors"
	"net/http"
	"net/url"
)

// A mock authorization provider
type testAuthz map[string][]testRole

type testRole string

func (a testAuthz) ValidScope(scope ...string) bool {
	for _, s := range scope {
		if _, ok := a[s]; !ok {
			return false
		}
	}
	return true
}

// Create scopeset for the user's given roles
func (a testAuthz) ScopeSetFor(u *User) ScopeSet {
	s := make(testAuthz)
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
type testAuthn []*User

// Authnredirect sets a User under a randomly created byte slice
func (a testAuthn) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// User returns the previously set user
func (a testAuthn) User(r *http.Request, state []byte) (*User, error) {
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
type testClientMap []*Client

func (m testClientMap) Get(id string) (*Client, error) {
	for _, c := range m {
		if c.Id == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}
