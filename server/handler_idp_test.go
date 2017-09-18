package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func testIdPHandler() *idpHandler {
	baseURL, _ := url.Parse("http://testserver/idp")
	return &idpHandler{baseHandler(), testIdProvider(), baseURL, accessTokenEnc().accessTokenEncoder}
}

func TestEmptyRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/idp", nil)
	w := httptest.NewRecorder()
	testIdPHandler().ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("empty request", t, resp, "token parameter missing.")
}

func TestInvalidStateToken(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/idp?token=test", nil)
	w := httptest.NewRecorder()
	testIdPHandler().ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("invalid state token", t, resp, "invalid state token.")
}

type testIdPRequest struct {
	State    *authorizationState
	UID      string
	Validate func(r *http.Response)
}

func (req *testIdPRequest) Do() error {
	handler := testIdPHandler()
	token := "test"
	store := handler.stateStore
	if err := store.persist(token, req.State); err != nil {
		return err
	}
	request := httptest.NewRequest("GET", "http://testserver/idp", nil)
	q := request.URL.Query()
	q.Set("token", "test")
	if req.UID != "" {
		q.Set("uid", req.UID)
	}
	request.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	req.Validate(w.Result())
	return nil
}

func TestIdPHandler(t *testing.T) {
	var tests = []*testIdPRequest{
		// Bad redirect_uri (must be checked during registration and during initial
		// authz request)
		&testIdPRequest{
			State: &authorizationState{
				RedirectURI: ":",
			},
			Validate: func(r *http.Response) {
				if r.StatusCode != 500 {
					t.Fatalf(
						"Bad redirect_uri: status should be 500, is %d", r.StatusCode,
					)
				}
			},
		},
		// Authentication error
		&testIdPRequest{
			State: &authorizationState{},
			UID:   "baduser",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"authentication error", t, r, "access_denied",
					"couldn't authenticate user",
				)
			},
		},
		// Valid request, check for scopes
		&testIdPRequest{
			State: &authorizationState{
				Scope: []string{
					"scope:1", "scope:4", "scope:6", "scope:7", "doesntexist",
				},
				State: "Dinah's key",
			},
			UID: "user:1",
			Validate: func(r *http.Response) {
				if r.StatusCode != 303 {
					t.Fatalf(
						"valid: unexpected response code (expected 303, got %d)",
						r.StatusCode,
					)
				}
				location, ok := r.Header["Location"]
				if !ok {
					t.Fatal("Got 303 but no Location header")
				}
				l, err := url.Parse(location[0])
				if err != nil {
					t.Fatal(err)
				}
				q, err := url.ParseQuery(l.Fragment)
				if err != nil {
					t.Fatal("Can't parse fragment")
				}
				if accessToken, ok := q["access_token"]; !ok {
					t.Fatalf("access_token missing: %s", location)
				} else {
					enc := accessTokenEnc()
					if _, _, err := enc.decodeJWT(accessToken[0]); err != nil {
						t.Fatal(err)
					}
				}
				if tokenType, ok := q["token_type"]; !ok {
					t.Fatal("token_type missing")
				} else if tokenType[0] != "bearer" {
					t.Fatal("token_type should be bearer")
				}
				if expiresIn, ok := q["expires_in"]; !ok {
					t.Fatal("expires_in missing")
				} else if expiresIn[0] != "5" {
					t.Fatal("expected expires_in to be 5, is %s", expiresIn[0])
				}
				if scope, ok := q["scope"]; !ok {
					t.Fatal("scope missing")
				} else {
					expected := map[string]struct{}{
						"scope:1": struct{}{},
						"scope:4": struct{}{},
						"scope:6": struct{}{},
					}
					received := make(map[string]struct{})
					for _, r := range strings.Split(scope[0], " ") {
						received[r] = struct{}{}
					}
					if !reflect.DeepEqual(received, expected) {
						t.Fatal(
							"valid: unexpected scopes (rec: %s, exp: %s)",
							received, expected,
						)
					}
				}
				if state, ok := q["state"]; !ok {
					t.Fatal("state missing")
				} else if state[0] != "Dinah's key" {
					t.Fatal("Unexpected state: %s", state[0])
				}
			},
		},
	}
	for _, test := range tests {
		if err := test.Do(); err != nil {
			t.Fatalf("Error creating test request: %s", err)
		}
	}
}
