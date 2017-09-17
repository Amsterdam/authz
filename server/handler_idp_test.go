package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

var testIdPHandler *idpHandler

func init() {
	baseURL, _ := url.Parse("http://testserver/idp")

	testIdPHandler = &idpHandler{baseHandler(), testIdProvider(), baseURL, accessTokenEnc()}
}

func TestEmptyRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/idp", nil)
	w := httptest.NewRecorder()
	testIdPHandler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("empty request", t, resp, "token parameter missing.")
}

func TestInvalidStateToken(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/idp?token=test", nil)
	w := httptest.NewRecorder()
	testIdPHandler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("invalid state token", t, resp, "invalid state token.")
}

type testIdPRequest struct {
	State    *authorizationState
	UID      string
	Validate func(r *http.Response)
}

func (req *testIdPRequest) Do() error {
	token := "test"
	store := testIdPHandler.stateStore
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
	testIdPHandler.ServeHTTP(w, request)
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
	}
	for _, test := range tests {
		if err := test.Do(); err != nil {
			t.Fatalf("Error creating test request: %s", err)
		}
	}
}
