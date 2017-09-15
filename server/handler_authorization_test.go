package server

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var handler *authorizationHandler

func init() {
	clients := testClientMap{
		&Client{
			Id:        "testclient1",
			Redirects: []string{"http://testclient/"},
			GrantType: "token",
		},
		&Client{
			Id:        "testclient2",
			Redirects: []string{"http://testclient2/a", "http://testclient2/b"},
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
	baseHandler := &oauth20Handler{clients, authz, stateStore}

	authn := testAuthn{
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
	Validate     func(r *http.Response)
}

func (r *testAuthzRequest) Do() {
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
	r.Validate(w.Result())
}

func TestAuthorizationHandler(t *testing.T) {
	var tests = []*testAuthzRequest{
		// No input at all
		&testAuthzRequest{
			Validate: func(r *http.Response) {
				if r.StatusCode != 400 {
					t.Fatalf("Unexpected response on empty request: %s", r.Status)
				}
				if body, err := ioutil.ReadAll(r.Body); err != nil {
					t.Fatal(err)
				} else if string(body) != "missing client_id" {
					t.Fatalf("Unexpected body: %s", body)
				}
			},
		},
		// Invalid client_id
		&testAuthzRequest{
			ClientId: "bad",
			Validate: func(r *http.Response) {
				if r.StatusCode != 400 {
					t.Fatalf("Unexpected response on empty request: %s", r.Status)
				}
				if body, err := ioutil.ReadAll(r.Body); err != nil {
					t.Fatal(err)
				} else if string(body) != "invalid client_id" {
					t.Fatalf("Unexpected body: %s", body)
				}
			},
		},
		// Missing redirect_uri
		&testAuthzRequest{
			ClientId: "testclient2",
			Validate: func(r *http.Response) {
				if r.StatusCode != 400 {
					t.Fatalf("Unexpected response on empty request: %s", r.Status)
				}
				if body, err := ioutil.ReadAll(r.Body); err != nil {
					t.Fatal(err)
				} else if string(body) != "missing or invalid redirect_uri" {
					t.Fatalf("Unexpected body: %s", body)
				}
			},
		},
	}
	for _, t := range tests {
		t.Do()
	}
}
