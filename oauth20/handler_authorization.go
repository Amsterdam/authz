package oauth20

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func (h *oauth20Handler) serveAuthorizationRequest(
	w http.ResponseWriter, r *http.Request,
) {
	if r.Method != "GET" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var (
		query       = r.URL.Query()
		client      *Client
		state       string
		scopes      []string
		redirectURI *url.URL
		idp         IdP
	)
	// client_id
	if clientId, ok := query["client_id"]; ok {
		if c, err := h.clientMap.Get(clientId[0]); err == nil {
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
		if idp, ok = h.idps[idpId[0]]; !ok {
			h.errorResponse(w, redirectURI, "invalid_request", "unknown idp_id")
			return
		}
	} else {
		h.errorResponse(w, redirectURI, "invalid_request", "idp_id missing")
		return
	}
	// Create a new authentication session
	// state of authz request
	authzState := &authorizationState{
		ClientId:     client.Id,
		RedirectURI:  redirectURI.String(),
		ResponseType: client.GrantType,
		Scope:        scopes,
		State:        state,
		IdPID:        idp.ID(),
	}
	redir, err := h.createSession(idp, authzState)
	if err != nil {
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}

	w.Header().Set("Location", redir)
	w.WriteHeader(http.StatusSeeOther)
}
