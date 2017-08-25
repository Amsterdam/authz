package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/client"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

var grants = map[string]struct{}{
	"code":  {},
	"token": {},
}

type AuthorizationHandler struct {
	clients        client.OAuth20ClientMap
	authnRedirects map[string]AuthnRedirect
	//	scopes  interface{}
	store storage.Transient
}

func (a *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	request := &AuthorizationRequest{
		Request:        r,
		clients:        a.clients,
		authnRedirects: a.authnRedirects,
	}
	var err error
	params := &AuthorizationState{}
	if params.ClientId, err = request.ClientId(); err != nil {
		log.Printf("OAuth 2.0 bad request: %s", err)
		HTTP400BadRequest(w, fmt.Sprintf("missing or invalid client_id: %s", err))
		return
	}
	if params.RedirectURI, err = request.RedirectURI(); err != nil {
		log.Printf("OAuth 2.0 bad request: %s", err)
		HTTP400BadRequest(w, fmt.Sprintf("missing or invalid redirect_uri: %s", err))
		return
	}
	redirectURI, err := url.Parse(params.RedirectURI)
	if err != nil {
		log.Printf("OAuth 2.0 unexpected error: %s", err)
		HTTP400BadRequest(w, fmt.Sprintf("Could not parse redirect URI: %s", params.RedirectURI))
		return
	}
	if params.ResponseType, err = request.ResponseType(); err != nil {
		if e, ok := err.(*OAuth20Error); ok {
			log.Printf("OAuth 2.0 bad request: %s", err)
			OAuth20ErrorResponse(w, e, redirectURI)
			return
		}
		log.Fatal(err)
	}
	if params.State, err = request.State(); err != nil {
		if e, ok := err.(*OAuth20Error); ok {
			log.Printf("OAuth 2.0 bad request: %s", err)
			OAuth20ErrorResponse(w, e, redirectURI)
			return
		}
		log.Fatal(err)
	}
	authnRedirect, err := request.AuthnRedirect()
	if err != nil {
		log.Printf("OAuth 2.0 server error: %s", err)
		OAuth20ErrorResponse(w, &OAuth20Error{ERRCODE_SERVER_ERROR, "oops!"}, redirectURI)
		return
	}
	authnRedirect(params, w)
}

type AuthorizationRequest struct {
	*http.Request

	clients        client.OAuth20ClientMap
	authnRedirects map[string]AuthnRedirect

	idpId string

	clientId     string
	redirectURI  string
	responseType string
	scope        []string
	state        string
}

func (r *AuthorizationRequest) ClientId() (string, error) {
	if r.clientId != "" {
		return r.clientId, nil
	}
	// request query string
	q := r.URL.Query()
	// extract client id
	if clientId, ok := q["client_id"]; ok {
		if _, err := r.clients.Get(clientId[0]); err != nil {
			return "", err
		}
		r.clientId = clientId[0]
		return clientId[0], nil
	}
	return "", errors.New("client_id missing")
}

func (r *AuthorizationRequest) RedirectURI() (string, error) {
	if r.redirectURI != "" {
		return r.redirectURI, nil
	}
	// request query string
	q := r.URL.Query()
	// extract redirect_uri
	if redirectURI, ok := q["redirect_uri"]; ok {
		if err := r.validateRedirectURI(redirectURI[0]); err != nil {
			return "", err
		}
		r.redirectURI = redirectURI[0]
		return redirectURI[0], nil
	}
	// No redirect_uri found, return the registered one if possible
	if redirectURI, err := r.redirectURIFromClient(); err == nil {
		return redirectURI, nil
	}
	// Couldn't decide on redirect_uri
	return "", errors.New("redirect_uri missing")
}

func (r *AuthorizationRequest) validateRedirectURI(redirectURI string) error {
	clientId, err := r.ClientId()
	if err != nil {
		return err
	}
	clientData, err := r.clients.Get(clientId)
	if err != nil {
		return err
	}
	for _, registeredRedirectURI := range clientData.Redirects {
		if registeredRedirectURI == redirectURI {
			return nil
		}
	}
	return errors.New("Invalid redirect URI")
}

func (r *AuthorizationRequest) redirectURIFromClient() (string, error) {
	clientId, err := r.ClientId()
	if err != nil {
		return "", err
	}
	clientData, err := r.clients.Get(clientId)
	if err != nil {
		return "", err
	}
	if len(clientData.Redirects) != 1 {
		return "", errors.New("Client has more than one registered redirect_uri")
	}
	return clientData.Redirects[0], nil
}

func (r *AuthorizationRequest) ResponseType() (string, error) {
	if r.responseType != "" {
		return r.responseType, nil
	}
	// request query string
	q := r.URL.Query()
	// extract response_type
	if responseType, ok := q["response_type"]; ok {
		if _, ok := grants[responseType[0]]; ok {
			r.responseType = responseType[0]
			return responseType[0], nil
		}
		return "", &OAuth20Error{ERRCODE_INVALID_SCOPE, "response_type not supported"}
	}
	return "", &OAuth20Error{ERRCODE_INVALID_REQUEST, "response_type missing"}
}

func (r *AuthorizationRequest) State() (string, error) {
	if r.state != "" {
		return r.state, nil
	}
	// request query string
	q := r.URL.Query()
	// extract state
	if state, ok := q["state"]; ok {
		if len(state[0]) >= 8 {
			r.state = state[0]
			return state[0], nil
		}
		return "", &OAuth20Error{ERRCODE_INVALID_REQUEST, "state should be at least 8 characters long"}
	}
	return "", &OAuth20Error{ERRCODE_INVALID_REQUEST, "state missing"}
}

func (r *AuthorizationRequest) AuthnRedirect() (AuthnRedirect, error) {
	// request query string
	q := r.URL.Query()
	// extract idp
	if idpId, ok := q["idp_id"]; ok {
		if redir, ok := r.authnRedirects[idpId[0]]; ok {
			return redir, nil
		}
		return nil, &OAuth20Error{ERRCODE_INVALID_REQUEST, "invalid idp_id"}
	}
	return nil, &OAuth20Error{ERRCODE_INVALID_REQUEST, "idp_id missing"}
}
