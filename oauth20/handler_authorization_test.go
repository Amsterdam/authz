package oauth20

/*
type testAuthzRequest struct {
	ClientId     string
	RedirectURI  string
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
	if r.IdpId != "" {
		q.Set("idp_id", r.IdpId)
	}
	req.URL.RawQuery = q.Encode()
	w := httptest.NewRecorder()
	testAuthzHandler.ServeHTTP(w, req)
	r.Validate(w.Result())
}

func TestAuthorizationHandler(t *testing.T) {
	var tests = []*testAuthzRequest{
		// No input at all
		&testAuthzRequest{
			Validate: func(r *http.Response) {
				expectBadRequest(
					"no parameters", t, r, "missing client_id",
				)
			},
		},
		// Invalid client_id
		&testAuthzRequest{
			ClientId: "bad",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"invalid redirect_uri", t, r, "invalid client_id",
				)
			},
		},
		// Missing redirect_uri
		&testAuthzRequest{
			ClientId: "testclient2",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"missing redirect_uri", t, r, "missing or invalid redirect_uri",
				)
			},
		},
		// Bad redirect_uri
		&testAuthzRequest{
			ClientId:    "testclient1",
			RedirectURI: "http://bad/",
			Validate: func(r *http.Response) {
				expectBadRequest(
					"bad redirect_uri", t, r, "missing or invalid redirect_uri",
				)
			},
		},
		// Invalid redirect_uri (should be caught at client registration as well)
		&testAuthzRequest{
			ClientId:    "testclient2",
			RedirectURI: ":",
			Validate: func(r *http.Response) {
				if r.StatusCode != 500 {
					t.Fatalf(
						"invalid redirect_uri: got %s, expected 500", r.StatusCode,
					)
				}
			},
		},
		// Missing response_type
		&testAuthzRequest{
			ClientId: "testclient1",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing response_type", t, r, "invalid_request",
					"response_type missing",
				)
			},
		},
		// Unspported response_type
		&testAuthzRequest{
			ClientId:     "testclient1",
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
			ClientId:     "testclient1",
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
			ClientId:     "testclient1",
			ResponseType: "token",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"missing idp_id", t, r, "invalid_request", "idp_id missing",
				)
			},
		},
		// Unknown idp_id
		&testAuthzRequest{
			ClientId:     "testclient1",
			ResponseType: "token",
			IdpId:        "invalid",
			Validate: func(r *http.Response) {
				expectErrorResponse(
					"unknown idp_id", t, r, "invalid_request", "unknown idp_id",
				)
			},
		},
		// Successful request
		&testAuthzRequest{
			ClientId:     "testclient1",
			ResponseType: "token",
			IdpId:        "idp",
			Validate: func(r *http.Response) {
				if r.StatusCode != 303 {
					t.Fatalf(
						"valid request: Unexpected response (expected 303, got %s)",
						r.StatusCode,
					)
				}
			},
		},
	}
	for _, test := range tests {
		test.Do()
	}
}
*/
