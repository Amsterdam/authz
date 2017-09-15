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
	/*
		client_id
			REQUIRED.  The client identifier as described in Section 2.2.
	*/
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

	/*
		redirect_uri
			If multiple redirection URIs have been registered, if only part of
			the redirection URI has been registered, or if no redirection URI has
			been registered, the client MUST include a redirection URI with the
			authorization request using the "redirect_uri" request parameter.

		The code below only does string matching so complete URLs must be registered
		(which is suggested by the RFC: The authorization server SHOULD require the
		client to provide the complete redirection URI).
	*/
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

	/*
		response_type
			REQUIRED.  Value MUST be set to "token".
	*/
	responseType, ok := query["response_type"]
	if !ok {
		h.errorResponse(w, redirectURI, "invalid_request", "response_type missing")
		return
	}
	if responseType[0] != client.GrantType {
		h.errorResponse(w, redirectURI, "unsupported_response_type", "response_type not supported for client")
		return
	}

	/*
		state
			RECOMMENDED.  An opaque value used by the client to maintain
			state between the request and callback.  The authorization
			server includes this value when redirecting the user-agent back
			to the client.  The parameter SHOULD be used for preventing
			cross-site request forgery as described in Section 10.12.
	*/
	if s, ok := query["state"]; ok {
		state = s[0]
	}

	/*
		scope
			OPTIONAL.  The scope of the access request as described by
			Section 3.3.

			The value of the scope parameter is expressed as a list of space-
			delimited, case-sensitive strings.  The strings are defined by the
			authorization server.  If the value contains multiple space-delimited
			strings, their order does not matter, and each string adds an
			additional access range to the requested scope.

				scope       = scope-token *( SP scope-token )
				scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
	*/
	scopeMap := make(map[string]struct{})
	if s, ok := query["scope"]; ok {
		for _, scope := range strings.Split(s[0], " ") {
			if !h.authz.ValidScope(scope) {
				h.errorResponse(w, redirectURI, "invalid_scope", fmt.Sprintf("invalid scope: %s", scope))
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
	reqState := &authorizationState{
		ClientId:     client.Id,
		RedirectURI:  redirectURI.String(),
		ResponseType: client.GrantType,
		Scope:        scopes,
		State:        state,
		IdPState:     session.IdPState,
	}
	if err := h.stateStore.persist(session.Token, reqState); err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}

	w.Header().Set("Location", session.Redir)
	w.WriteHeader(http.StatusSeeOther)
}
