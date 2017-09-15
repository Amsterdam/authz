package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DatapuntAmsterdam/goauth2/server/servertest"
)

var handler *authorizationHandler

func init() {
	clients := servertest.ClientMap{
		*Client{
			Id:        "testclient",
			Redirects: []string{"http://testclient/"},
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
	authz := servertest.Authz{
		"scope:1": []Role{Role("role:1"), Role("role:4")},
		"scope:2": []Role{Role("role:1"), Role("role:5")},
		"scope:3": []Role{Role("role:2"), Role("role:6")},
		"scope:4": []Role{Role("role:2")},
		"scope:5": []Role{Role("role:3"), Role("role:6")},
		"scope:6": []Role{Role("role:3"), Role("role:5")},
		"scope:7": []Role{Role("role:4")},
	}
	stateStore := newStateStorage(newStateMap(), 1*time.Duration)
	baseHandler := &oauth20Handler{clients, authz, stateStore}

	authn := servertest.Authn{
		&User{"user:1", []string{"role:1", "role:2", "role:3"}},
		&User{"user:2", []string{"role:4", "role:5", "role:6"}},
	}
	baseURL, _ := url.Parse("http://testserver/idp")
	atEnc := newAccessTokenEncoder([]byte("secret"), 5, "testissuer")

	idps := map[string]*idpHandler{
		"idp": &idpHandler{baseHandler, authn, baseURL, atEnc},
	}
	handler = &authorizationHandler{baseHandler, idps}
}

type testAuthzRequest struct {
	ClientId     string
	RedirectUri  string
	ResponseType string
	State        string
	Scope        []string
	IdpId        string
}

func (r *testAuthzRequest) Do() http.Response {
	req := httptest.NewRequest("GET", "http://test/", nil)
	q := req.URL.Query()
	if r.ClientId != "" {
		q.Set("client_id", r.ClientId)
	}
	if r.RedirectUri != "" {
		q.Set("redirect_uri", r.RedirectUri)
	}
	if r.ResponseType != "" {
		q.Set("response_type", r.ResponseType)
	}
	if r.State != "" {
		q.Set("state", r.State)
	}
	if len(r.Scope) > 0 {
		q.Set("scope", strings.Join(r.Scope, " "))
	}
	if r.IdpId != "" {
		q.Set("idp_id", r.IdpId)
	}
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w.Result()
}

func TestAuthorizationHandler(t *testing.T) {
	var tests = []struct {
		params   *testAuthzRequest
		expected func(r *http.Response)
	}{
		{
			&testAuthzRequest{},
			func(r *http.Response) {
				if r.StatusCode != 400 {
					t.Fatalf("Unexpected response on empty request: %s", r.Status)
				}
			},
		},
	}
	for _, t := range tests {
		t.expected(t.params.Do)
	}
}
