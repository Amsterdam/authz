package rfc6749

import (
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/rfc6749/idp"
	"github.com/DatapuntAmsterdam/goauth2/rfc6749/transientstorage"
)

// Supported grant types & handlers
var grantHandlers = map[string]func() *AuthorizationResponse{
	"code":  func() *AuthorizationResponse { return nil },
	"token": func() *AuthorizationResponse { return nil },
}

// Error codes
const (
	ERRCODE_INVALID_REQUEST           = "invalid_request"
	ERRCODE_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	ERRCODE_ACCESS_DENIED             = "access_denied"
	ERRCODE_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	ERRCODE_INVALID_SCOPE             = "invalid_scope"
	ERRCODE_SERVER_ERROR              = "server_error"
	ERRCODE_TEMPORARILY_UNAVAILABLE   = "temporarily_unavailable"
)

// Characters used for random request identifiers.
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// AuthorizationResponse is an HTTP response that should be returned to the client.
type AuthorizationResponse struct {
	status int
	header map[string][]string
	body   []byte
}

// Write writes the response onto the given ResponseWriter.
func (r *AuthorizationResponse) Write(w http.ResponseWriter) {
	headers := w.Header()
	for header, values := range r.header {
		for _, value := range values {
			headers.Add(header, value)
		}
	}
	w.WriteHeader(r.status)
	w.Write(r.body)
}

type OAuth2ClientConfig struct {
	Redirects []string `toml:"redirects"`
}

// Resource handlers for the OAuth 2.0 service.
type OAuth20Resources struct {
	idps    map[string]idp.IdP
	clients map[string]OAuth2ClientConfig
	kvStore transientstorage.TransientStorage
	// ScopesMap ScopeMap
	AuthorizationRequest http.Handler
}

func NewOAuth20Resources(idps map[string]idp.IdP, clients map[string]OAuth2ClientConfig, kvStore transientstorage.TransientStorage) *OAuth20Resources {
	oauth20Resources := &OAuth20Resources{idps: idps, clients: clients, kvStore: kvStore}
	oauth20Resources.AuthorizationRequest = http.HandlerFunc(oauth20Resources.authorizationRequest)
	return oauth20Resources
}

// AuthorizationRequest handles an OAuth 2.0 authorization request.
func (h OAuth20Resources) authorizationRequest(w http.ResponseWriter, r *http.Request) {
	// Create an authorization request
	authzReq, err := h.NewAuthorizationRequest(r)
	if err != nil {
		log.Printf("Authz request error: %s -> %s", r.RequestURI, err)
	} else {
		params := &transientstorage.AuthorizationParams{
			ClientId:     authzReq.ClientId,
			RedirectURI:  authzReq.RedirectURI,
			ResponseType: authzReq.ResponseType,
			Scope:        authzReq.Scope,
			State:        authzReq.State,
		}
		if err := h.kvStore.SetAuthorizationParams(authzReq.Id, params); err != nil {
			authzReq.SetErrorResponse(ERRCODE_SERVER_ERROR, "server error")
			log.Printf("Authz request error: %s", err)
		}
	}
	authzReq.Response.Write(w)
}

// AuthorizationRequest handles an authorization request.
type AuthorizationRequest struct {
	// An identifier to be used
	Id string
	// Expected params
	ClientId     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
	// Request query and response
	query    url.Values
	Response *AuthorizationResponse
	// Context.
	idProvider   idp.IdP
	oauth2Client *OAuth2ClientConfig
	kvStoreIdp   transientstorage.TransientStorageIdP
	redirectURI  *url.URL
}

func (h *OAuth20Resources) NewAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	// placeholder
	var err error

	q := r.URL.Query()
	authzReq := &AuthorizationRequest{query: q, Response: &AuthorizationResponse{}}

	// Validate and set client_id and oauth2client
	if clientId, ok := q["client_id"]; ok {
		if c, ok := h.clients[clientId[0]]; ok {
			authzReq.oauth2Client = &c
			authzReq.ClientId = clientId[0]
		} else {
			err = errors.New("unknown client_id")
		}
	} else {
		err = errors.New("client_id missing")
	}
	if err != nil {
		authzReq.SetBadRequest(err.Error())
		return authzReq, err
	}

	// Validate and set redirect_uri
	var redirectURI string
	if redirect, ok := q["redirect_uri"]; ok {
		for _, registeredRedirectURI := range authzReq.oauth2Client.Redirects {
			if registeredRedirectURI == redirect[0] {
				redirectURI = redirect[0]
				break
			}
		}
	} else if len(authzReq.oauth2Client.Redirects) == 1 {
		redirectURI = authzReq.oauth2Client.Redirects[0]
	}
	if redirectURI != "" {
		if redir, parseErr := url.Parse(redirectURI); parseErr == nil {
			authzReq.RedirectURI = redirectURI
			authzReq.redirectURI = redir
		} else {
			err = errors.New(fmt.Sprintf("invalid redirect_uri in client configuration: %s", authzReq.oauth2Client.Redirects[0]))
		}
	} else {
		err = errors.New("must provide a valid redirect_uri for this client_id")
	}
	if err != nil {
		authzReq.SetBadRequest(err.Error())
		return authzReq, err
	}

	// Validate and set idProvider property.
	if idpId, ok := q["idp_id"]; ok {
		if i, ok := h.idps[idpId[0]]; ok {
			authzReq.idProvider = i
			// Set the KV store for this IdP
			authzReq.kvStoreIdp = h.kvStore.StorageForIdP(idpId[0])
		} else {
			err = errors.New("unknown idp_id")
		}
	} else {
		err = errors.New("idp_id missing")
	}
	if err != nil {
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	// Validate and set response_type
	if responseType, ok := q["response_type"]; ok {
		if _, ok := grantHandlers[responseType[0]]; ok {
			authzReq.ResponseType = responseType[0]
		} else {
			err = errors.New("response_type not supported")
			authzReq.SetErrorResponse(ERRCODE_UNSUPPORTED_RESPONSE_TYPE, err.Error())
			return authzReq, err
		}
	} else {
		err = errors.New("response_type missing")
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	// Validate and set state
	if state, ok := q["state"]; ok {
		if len(state[0]) >= 8 {
			authzReq.State = state[0]
		} else {
			err = errors.New("state should be at least 8 characters long")
		}
	} else {
		err = errors.New("state missing")
	}
	if err != nil {
		authzReq.SetErrorResponse(ERRCODE_INVALID_REQUEST, err.Error())
		return authzReq, err
	}

	authzReq.setIdpRedirectResponse()

	return authzReq, err
}

// setIdpRedirectResponse sets a 303 See Other response.
func (r *AuthorizationRequest) setIdpRedirectResponse() {
	// Create an opaque token that can be used to store / fetch request params.
	reqId := make([]byte, 16)
	for i := range reqId {
		reqId[i] = letters[rand.Int63()%int64(len(letters))]
	}
	r.Id = string(reqId)
	// Get the IdP's redirect URI
	cb, _ := url.Parse("http://localhost")
	authnRedir, _ := r.idProvider.AuthnRedirect(r.Id, *cb, r.kvStoreIdp)
	// Create and set the response
	if r.Response.header == nil {
		r.Response.header = make(map[string][]string)
	}
	r.Response.status = http.StatusSeeOther
	r.Response.header["Location"] = []string{authnRedir}
}

// SetBadRequest sets a 404 Bad Request response.
func (r *AuthorizationRequest) SetBadRequest(body string) {
	r.Response.status = http.StatusBadRequest
	r.Response.body = []byte(body)
}

// SetErrorResponse sets a 303 See Other error response with
// error=[errorType]&error_description=[description] query params.
func (r *AuthorizationRequest) SetErrorResponse(errorType string, description string) {
	if r.Response.header == nil {
		r.Response.header = make(map[string][]string)
	}
	query := r.redirectURI.Query()
	query.Set("error", errorType)
	query.Set("error_description", description)
	r.redirectURI.RawQuery = query.Encode()
	r.Response.status = http.StatusSeeOther
	r.Response.header["Location"] = []string{r.redirectURI.String()}
}
