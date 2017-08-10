package service

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/config"
	"github.com/DatapuntAmsterdam/goauth2/idp"
)

// Supported grant types
const (
	AUTHORIZATION_CODE_GRANT = "code"
	IMPLICIT_GRANT           = "token"
)

// An OAuth2Error is an error that contains both an error code and description.
type OAuth2Error struct {
	ErrorCode   string
	Description string
}

// Error() is part of the error interface.
func (e OAuth2Error) Error() string {
	return fmt.Sprintf("OAuth 2.0 error: %s (%s)", e.ErrorCode, e.Description)
}

// An OAuth2Response is an HTTP response that should be returned to the client.
type OAuth2Response struct {
	Status int
	Header map[string][]string
	Body   []byte
}

// Resource handlers for the OAuth 2.0 service.
type OAuth2 struct {
	Handler *Handler
	idps    map[string]idp.IdP
	clients map[string]config.OAuth2Client
	// ScopesMap ScopeMap
}

// OAuth 2.0 resources.
//
// NewOAuth2() creates a Handler and registers all its resources.
func NewOAuth2(conf *config.Config) (*OAuth2, error) {
	idps, err := idp.IdPMap(conf)
	if err != nil {
		return nil, err
	}
	oauth2 := &OAuth2{
		Handler: NewHandler(),
		idps:    idps,
		clients: conf.Client,
	}

	oauth2.Handler.addResources(
		Resource{
			"authorizationrequest", "/authorize",
			methodHandler{
				"GET": oauth2.authorizationRequest,
			},
		},
	)
	return oauth2, nil
}

// authorizationRequest handles an OAuth 2.0 authorization request.
func (h *OAuth2) authorizationRequest(w http.ResponseWriter, r *http.Request) {

	// First check whether client_id is present and valid
	var client config.OAuth2Client
	q := r.URL.Query()
	if clientId, ok := q["client_id"]; ok {
		if c, ok := h.clients[clientId[0]]; ok {
			client = c
		}
	}
	if len(client.Redirects) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Must provide a valid client_id"))
		return
	}

	// Now validate the redirect URI

	// Now make sure idp_id is present and valid
	var authnProvider idp.IdP
	if idpId, ok := q["idp_id"]; ok {
		if i, ok := h.idps[idpId[0]]; ok {
			authnProvider = i
		}
	}
	if authnProvider == nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Must provide an idp_id"))
		return
	}
	authzReq := AuthzRequest{req: r}
	response := authzReq.Response()
	headers := w.Header()
	for header, values := range response.Header {
		for _, value := range values {
			headers.Add(header, value)
		}
	}
	w.WriteHeader(response.Status)
	w.Write(response.Body)
}

// AuthzRequest handles an authorization request.
type AuthzRequest struct {
	req         *http.Request
	clientId    string
	redirectURI url.URL
	scope       []string
	state       string
}

// Response generates a response that is appropriate for this authorization request.
func (r *AuthzRequest) Response() *OAuth2Response {
	response := &OAuth2Response{}
	responseType, err := r.responseType()
	if err != nil {
		response.Status = http.StatusBadRequest
		response.Body = []byte("trouble")
		return response
	}
	response.Status = http.StatusOK
	response.Body = append([]byte(responseType))
	return response
}

func (r *AuthzRequest) responseType() (responseType string, err error) {
	res, ok := r.req.URL.Query()["response_type"]
	if !ok {
		err = OAuth2Error{"invalid_request", "Missing response_type request parameter."}
	} else {
		responseType = res[0]
	}
	return
}
