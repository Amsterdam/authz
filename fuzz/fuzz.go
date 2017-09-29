// +build gofuzz

package fuzz

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/amsterdam/authz/server"
)

var handler http.Handler

func init() {
	opts := options()
	s, err := server.New("", 1, opts...)
	if err != nil {
		panic(err)
	}
	handler = s.Handler()
}

func Fuzz(data []byte) (result int) {
	// Defer crashrecovery for invalid httptest.Requests
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(string); ok {
				if strings.Contains(err, "invalid NewRequest arguments") {
					result = -1
				}
			}
		}
	}()
	// parse data
	d := strings.Split(string(data), ",")
	if len(d) != 5 {
		return -1
	}
	client, redir, user, scope, state := d[0], d[1], d[2], d[3], d[4]
	// Create request
	req := httptest.NewRequest("GET", "/authorize", http.NoBody)
	q := req.URL.Query()
	q.Set("response_type", "token")
	q.Set("idp_id", "fuzz")
	q.Set("client_id", client)
	if redir != "" {
		q.Set("redirect_uri", redir)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	if state != "" {
		q.Set("state", state)
	}
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// read redirect to IdP
	resp := w.Result()
	if resp.StatusCode == 400 {
		return 0 // bad request
	}
	if resp.StatusCode == 302 {
		location := resp.Header.Get("Location")
		if location == "" {
			panic(resp)
		}
		if u, err := url.Parse(location); err != nil {
			panic(err)
		} else if u.Query().Get("error_code") != "" {
			return 0 // valid client, bad request
		} else {
			// Add uid for this request to query string
			q := u.Query()
			q.Set("uid", user)
			u.RawQuery = q.Encode()
			location = u.String()
		}
		// Cool! now lets try to get an access token
		req2 := httptest.NewRequest("GET", location, http.NoBody)
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		resp2 := w2.Result()
		if resp2.StatusCode != 302 {
			panic(resp)
		}
		location2 := resp2.Header.Get("Location")
		if location2 == "" {
			panic(resp)
		}
		if u, err := url.Parse(location2); err != nil {
			panic(resp)
		} else if u.Fragment == "" {
			panic(resp)
		} else {
			if _, err := url.ParseQuery(u.Fragment); err != nil {
				panic(err)
			} else {
				return 1
			}
		}
	}

	panic(resp)
}

// A fake authorization provider
type fuzzAuthz map[string]string

// Fake scopes
func (a fuzzAuthz) ValidScope(scope ...string) bool {
	for _, s := range scope {
		if _, ok := a[s]; !ok {
			return false
		}
	}
	return true
}

// Create scopeset for the user's given roles
func (a fuzzAuthz) ScopeSetFor(u *server.User) server.ScopeSet {
	s := make(fuzzAuthz)
	for _, r := range u.Roles {
		for scope, role := range a {
			if r == role {
				s[scope] = ""
			}
		}
	}
	return s
}

// Fake users
var users = []*server.User{
	&server.User{"user:1", []string{"role:1", "role:3"}},
	&server.User{"user:2", []string{"role2"}},
}

// A fake authentication provider
type fuzzAuthn map[string]*server.User

// Authnredirect sets a User under a randomly created byte slice
func (a fuzzAuthn) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

// User returns the previously set user
func (a fuzzAuthn) User(r *http.Request, state []byte) (*server.User, error) {
	if uid, ok := r.URL.Query()["uid"]; !ok {
		return nil, errors.New("Unknown uid")
	} else {
		for _, u := range users {
			if u.UID == uid[0] {
				return u, nil
			}
		}
	}
	return nil, errors.New("Invalid state")
}

// fake client map
type fuzzClientMap []*server.Client

// Get a fake client
func (m fuzzClientMap) Get(id string) (*server.Client, error) {
	for _, c := range m {
		if c.Id == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}

func options() []server.Option {
	var options []server.Option
	// Create components
	authz := fuzzAuthz{
		"scope:1": "role:1",
		"scope:2": "role:2",
		"scope:3": "role:3",
		"scope:4": "role:2",
		"scope:5": "role:1",
	}
	clients := fuzzClientMap{
		&server.Client{
			Id:        "client:1",
			Redirects: []string{"http://client:1/a", "http://client:1/b"},
			GrantType: "token",
		},
		&server.Client{
			Id:        "client:2",
			Redirects: []string{"http://client:2/"},
			GrantType: "token",
		},
	}
	authn := make(fuzzAuthn)
	baseURL, _ := url.Parse("http://localhost/")
	// set options
	options = append(options, server.BaseURL(*baseURL))
	options = append(options, server.AuthzProvider(authz))
	options = append(options, server.IdP("fuzz", authn))
	options = append(options, server.Clients(clients))
	return options
}
