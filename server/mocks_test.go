package server

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"testing"
	"time"
)

///////////////////////
// Mock objects
///////////////////////
func baseHandler() *oauth20Handler {
	clients := testClientMap{
		&Client{
			Id:        "testclient1",
			Redirects: []string{"http://testclient/"},
			GrantType: "token",
		},
		&Client{
			Id:        "testclient2",
			Redirects: []string{"http://testclient2/a", ":"},
			GrantType: "token",
		},
	}
	/*
		 scope 1 2 3 4 5 6 7
		role:1 x x
		role:2     x x
		role:3         x x
		role:4 x           x
		role:5   x       x
		role:6     x   x
	*/
	authz := testAuthz{
		"scope:1": []testRole{testRole("role:1"), testRole("role:4")},
		"scope:2": []testRole{testRole("role:1"), testRole("role:5")},
		"scope:3": []testRole{testRole("role:2"), testRole("role:6")},
		"scope:4": []testRole{testRole("role:2")},
		"scope:5": []testRole{testRole("role:3"), testRole("role:6")},
		"scope:6": []testRole{testRole("role:3"), testRole("role:5")},
		"scope:7": []testRole{testRole("role:4")},
	}
	stateStore := newStateStorage(newStateMap(), 10*time.Second)

	return &oauth20Handler{clients, authz, stateStore}
}

func testIdProvider() IdP {
	return &testIdP{
		&User{"user:1", []string{"role:1", "role:2", "role:3"}},
		&User{"user:2", []string{"role:4", "role:5", "role:6"}},
	}
}

func accessTokenEnc() *accessTokenEncoder {
	return newAccessTokenEncoder([]byte("secret"), 5, "testissuer")
}

///////////////////
// A mock authorization provider type
///////////////////
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

///////////////////
// A mock IdP type
///////////////////
type testIdP []*User

// Authnredirect sets a User under a randomly created byte slice
func (a testIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// User returns the previously set user
func (a testIdP) User(r *http.Request, state []byte) (*User, error) {
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

///////////////////
// Mock client map type
///////////////////
type testClientMap []*Client

func (m testClientMap) Get(id string) (*Client, error) {
	for _, c := range m {
		if c.Id == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}

///////////////////
// Helpers for parsing responses
///////////////////
func expectErrorResponse(
	title string, t *testing.T, r *http.Response, code string, description string) {
	if r.StatusCode != 303 {
		t.Fatalf(
			"%s: Unexpected response (expected 303, got %s)", title, r.StatusCode,
		)
	}
	location, ok := r.Header["Location"]
	if !ok {
		t.Fatalf("%s: HTTP 303 without Location header", title)
	}
	u, err := url.Parse(location[0])
	if err != nil {
		t.Fatalf("%s: couldn't parse Location header after 303", title)
	}
	q := u.Query()
	if c, ok := q["error"]; !ok {
		t.Fatalf("%s: not a valid oauth 2.0 error response: %s", title, u)
	} else if c[0] != code {
		t.Fatalf("%s: invalid error (expected %s, got %s)", title, code, c)
	}
	if d, ok := q["error_description"]; !ok {
		t.Fatalf("%s: not a valid oauth 2.0 error response: %s", title, u)
	} else if d[0] != description {
		t.Fatalf(
			"%s: invalid error_description (expected %s, got %s)", title,
			description, d,
		)
	}
}

func expectBadRequest(title string, t *testing.T, r *http.Response, xBody string) {
	if r.StatusCode != 400 {
		t.Fatalf("%s: Unexpected response (expected 400, got %s)", title, r.Status)
	}
	if xBody != "" {
		if body, err := ioutil.ReadAll(r.Body); err != nil {
			t.Fatal(err)
		} else if string(body) != xBody {
			t.Fatalf(
				"%s: Unexpected body (expected: %s, got: %s)", title, xBody, body,
			)
		}
	}
}
