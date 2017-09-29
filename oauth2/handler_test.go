package oauth2

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type testAuthzRequest struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Scope        []string
	IDPID        string
	Validate     func(r *http.Response)
}

func (r *testAuthzRequest) Do(handler http.Handler) {
	req := httptest.NewRequest("GET", "http://test/authorize", nil)
	q := req.URL.Query()
	if r.ClientID != "" {
		q.Set("client_id", r.ClientID)
	}
	if r.RedirectURI != "" {
		q.Set("redirect_uri", r.RedirectURI)
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
	if r.IDPID != "" {
		q.Set("idp_id", r.IDPID)
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
				expectBadRequest(
					"no parameters", t, r, "missing client_id\n",
				)
			},
		},
		// Invalid client_id
		&testAuthzRequest{
			ClientID: "bad",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"invalid redirect_uri", t, r, "invalid client_id\n",
				)
			},
		},
		// Missing redirect_uri
		&testAuthzRequest{
			ClientID: "testclient2",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"missing redirect_uri", t, r, "missing or invalid redirect_uri\n",
				)
			},
		},
		// Bad redirect_uri
		&testAuthzRequest{
			ClientID:    "testclient1",
			RedirectURI: "http://bad/",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"bad redirect_uri", t, r, "missing or invalid redirect_uri\n",
				)
			},
		},
		// Invalid redirect_uri (should be caught at client registration as well)
		&testAuthzRequest{
			ClientID:    "testclient2",
			RedirectURI: ":",
			Validate: func(r *http.Response) {
				if r.StatusCode != 500 {
					t.Fatalf(
						"invalid redirect_uri: got %d, expected 500", r.StatusCode,
					)
				}
			},
		},
		// Missing response_type
		&testAuthzRequest{
			ClientID: "testclient1",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing response_type", t, r, "invalid_request",
					"response_type missing",
				)
			},
		},
		// Unspported response_type
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "code",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"unsupported response_type", t, r, "unsupported_response_type",
					"response_type not supported for client",
				)
			},
		},
		// Invalid scope
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			Scope:        []string{"scope:1", "thisisnoscope"},
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"invalid scope", t, r, "invalid_scope", "invalid scope: thisisnoscope",
				)
			},
		},
		// Missing idp_id
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing idp_id", t, r, "invalid_request", "idp_id missing",
				)
			},
		},
		// Unknown idp_id
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			IDPID:        "invalid",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"unknown idp_id", t, r, "invalid_request", "unknown idp_id",
				)
			},
		},
		// Successful request
		&testAuthzRequest{
			ClientID:     "testclient1",
			ResponseType: "token",
			IDPID:        "testidp",
			Validate: func(r *http.Response) {
				if r.StatusCode != 303 {
					t.Fatalf(
						"valid request: Unexpected response (expected 303, got %d)",
						r.StatusCode,
					)
				}
			},
		},
	}
	handler := testHandler("test")
	for _, test := range tests {
		test.Do(handler)
	}
}

func TestEmptyCallbackRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/callback", nil)
	w := httptest.NewRecorder()
	handler := testHandler("test")
	handler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("empty callback", t, resp, "token parameter missing\n")
}

func TestInvalidCallbackToken(t *testing.T) {
	r := httptest.NewRequest("GET", "http://testserver/callback?token=test", nil)
	w := httptest.NewRecorder()
	handler := testHandler("test")
	handler.ServeHTTP(w, r)
	resp := w.Result()
	expectBadRequest("invalid callback token", t, resp, "invalid state token\n")
}

func TestValidCallbackToken(t *testing.T) {
	handler := testHandler("test")
	// First, make a valid authz request to get a valid token
	callback := validCallbackURL(t, handler)
	// Now make the valid callback request
	callbackReq := httptest.NewRequest("GET", callback, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, callbackReq)
	resp := w.Result()
	if resp.StatusCode != 303 {
		t.Fatalf(
			"valid callback token: Unexpected response (expected 303, got %d)",
			resp.StatusCode,
		)
	}
	locationHeaders, ok := resp.Header["Location"]
	if !ok {
		t.Fatalf("valid callback token: Unexpected response: %v", resp)
	}
	location := locationHeaders[0]
	if u, err := url.Parse(location); err != nil {
		t.Fatalf("valid callback token: Bad location: %v", err)
	} else {
		params, err := url.ParseQuery(u.Fragment)
		if err != nil {
			t.Fatalf("valid callback token: expected an accesstoken fragment: %v", u)
		}
		if _, ok := params["access_token"]; !ok {
			t.Fatalf("valid callback token: expected an accesstoken fragment: %v", u)
		}
	}
}

func validCallbackURL(t *testing.T, handler http.Handler) string {
	authzReq := httptest.NewRequest("GET", "http://test/authorize", nil)
	q := authzReq.URL.Query()
	q.Set("client_id", "testclient1")
	q.Set("redirect_uri", "http://testclient/")
	q.Set("response_type", "token")
	q.Set("state", "state")
	q.Set("scope", "scope:2 scope:4 scope:6 scope:7")
	q.Set("idp_id", "testidp")
	authzReq.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, authzReq)
	r := w.Result()
	locationHeaders, ok := r.Header["Location"]
	if !ok {
		t.Fatalf("creating callback url: Unexpected response: %v", r)
	}
	location := locationHeaders[0]
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("creating callback url: Bad location: %v", err)
	} else if !strings.HasSuffix(u.Path, "/callback") {
		t.Fatalf(
			"creating callback url: Expected to be redirected back to authz callback, got %s instead",
			location,
		)
	}
	q = u.Query()
	q.Set("uid", "user:1")
	u.RawQuery = q.Encode()
	return u.String()
}

func testHandler(tokenSecret string) http.Handler {
	var options []Option
	// IDP with two users
	idp := &testIDP{
		&User{"user:1", []string{"role:1", "role:2", "role:3"}},
		&User{"user:2", []string{"role:4", "role:5", "role:6"}},
	}
	options = append(options, IDProvider(idp))
	// Clients
	clients := testClientMap{
		&Client{
			ID:        "testclient1",
			Redirects: []string{"http://testclient/"},
			GrantType: "token",
		},
		&Client{
			ID:        "testclient2",
			Redirects: []string{"http://testclient2/a", ":"},
			GrantType: "token",
		},
	}
	options = append(options, Clients(clients))
	// Access token config
	options = append(options, AccessTokenConfig([]byte(tokenSecret), 10, "issuer"))
	// Authorization provider
	//	scope  1 2 3 4 5 6 7
	//	role:1 x x
	//	role:2     x x
	//	role:3         x x
	//	role:4 x           x
	//	role:5   x       x
	//	role:6     x   x
	authz := testAuthz{
		"scope:1": []testRole{testRole("role:1"), testRole("role:4")},
		"scope:2": []testRole{testRole("role:1"), testRole("role:5")},
		"scope:3": []testRole{testRole("role:2"), testRole("role:6")},
		"scope:4": []testRole{testRole("role:2")},
		"scope:5": []testRole{testRole("role:3"), testRole("role:6")},
		"scope:6": []testRole{testRole("role:3"), testRole("role:5")},
		"scope:7": []testRole{testRole("role:4")},
	}
	options = append(options, AuthzProvider(authz))

	handler, _ := Handler("http://test/", options...)
	return handler
}

///////
// testIDP
///////
type testIDP []*User

func (a testIDP) ID() string {
	return "testidp"
}

func (a testIDP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	return callbackURL, nil, nil
}

func (a testIDP) User(r *http.Request, state []byte) (*User, error) {
	uid, ok := r.URL.Query()["uid"]
	if !ok {
		return nil, errors.New("Unknown uid")
	}
	for _, u := range a {
		if u.UID == uid[0] {
			return u, nil
		}
	}
	return nil, errors.New("Invalid state")
}

///////
// testClientMap
///////
type testClientMap []*Client

func (m testClientMap) Get(id string) (*Client, error) {
	for _, c := range m {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, errors.New("unknown client")
}

///////
// A mock authorization provider type
///////
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

///////
// Helpers
///////
func expectErrorResponse(
	title string, t *testing.T, r *http.Response, code string, description string) {
	if r.StatusCode != 303 {
		t.Fatalf(
			"%s: Unexpected response (expected 303, got %d)", title, r.StatusCode,
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
