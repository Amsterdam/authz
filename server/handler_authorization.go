package server

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var grants = map[string]struct{}{
	"code":  {},
	"token": {},
}

type authorizationHandler struct {
	*oauth20Handler
	idps map[string]*idpHandler
}

func (h *authorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		query       = r.URL.Query()
		client      *Client
		state       string
		scopes      []string
		idpHandler  *idpHandler
		redirectURI *url.URL
	)
	// client_id
	if clientId, ok := query["client_id"]; ok {
		if c, err := h.clients.Get(clientId[0]); err == nil {
			client = c
		} else {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid client_id"))
			return
		}
	} else {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing client_id"))
		return
	}
	// redirect_uri
	var redirect string
	if redir, ok := query["redirect_uri"]; ok {
		for _, r := range client.Redirects {
			if redir[0] == r {
				redirect = r
				break
			}
		}
	} else if len(client.Redirects) == 1 {
		redirect = client.Redirects[0]
	}
	if redirect == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing or invalid redirect_uri"))
		return
	}
	if r, err := url.Parse(redirect); err != nil {
		log.Printf("ERROR: registered redirect is invalid: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	} else {
		redirectURI = r
	}
	// response_type
	responseType, ok := query["response_type"]
	if !ok {
		h.errorResponse(w, redirectURI, "invalid_request", "response_type missing")
		return
	}
	if responseType[0] != client.GrantType {
		h.errorResponse(
			w, redirectURI, "unsupported_response_type",
			"response_type not supported for client",
		)
		return
	}
	// state
	if s, ok := query["state"]; ok {
		state = s[0]
	}
	// scope
	scopeMap := make(map[string]struct{})
	if s, ok := query["scope"]; ok {
		for _, scope := range strings.Split(s[0], " ") {
			if !h.authz.ValidScope(scope) {
				h.errorResponse(
					w, redirectURI, "invalid_scope",
					fmt.Sprintf("invalid scope: %s", scope),
				)
				return
			}
			scopeMap[scope] = struct{}{}
		}
	}
	scopes = make([]string, len(scopeMap))
	i := 0
	for k := range scopeMap {
		scopes[i] = k
		i++
	}
	// Validate IdP and get idp handler url for this request
	if idpId, ok := query["idp_id"]; ok {
		if handler, ok := h.idps[idpId[0]]; ok {
			idpHandler = handler
		} else {
			h.errorResponse(w, redirectURI, "invalid_request", "unknown idp_id")
			return
		}
	} else {
		h.errorResponse(w, redirectURI, "invalid_request", "idp_id missing")
		return
	}
	// Create a new authentication session
	session, err := idpHandler.newAuthnSession()
	if err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}
	// Persist state of authz request
	authzState := &authorizationState{
		ClientId:     client.Id,
		RedirectURI:  redirectURI.String(),
		ResponseType: client.GrantType,
		Scope:        scopes,
		State:        state,
		IdPState:     session.IdPState,
	}
	if err := h.stateStore.persist(session.Token, authzState); err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}

	w.Header().Set("Location", session.Redir)
	w.WriteHeader(http.StatusSeeOther)
}
