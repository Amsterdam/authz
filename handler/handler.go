package handler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/client"
	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/scope"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

func NewOAuth20Handler(baseURL *url.URL, clients client.OAuth20ClientMap, idps idp.IdPMap, scopes scope.Set, store storage.Transient) (http.Handler, error) {
	handlers := make(map[string]http.Handler)
	// Create IdP handlers and store a map of AuthnRedirects.
	authnRedirects := make(map[string]AuthnRedirect)
	pathTempl := "oauth2/authorize/%s"
	for idpId, idp := range idps {
		u, err := baseURL.Parse(fmt.Sprintf(pathTempl, idpId))
		if err != nil {
			return nil, err
		}
		handler := &IdPHandler{idp, store, u}
		authnRedirects[idpId] = handler.AuthnRedirect
		handlers[u.Path] = handler
	}
	// Create authorization handler
	authzHandler := &AuthorizationHandler{clients, authnRedirects, scopes}
	u, err := baseURL.Parse("oauth2/authorize")
	if err != nil {
		return nil, err
	}
	handlers[u.Path] = authzHandler
	// Create mux handler and register handlers
	mux := http.NewServeMux()
	for pattern, handler := range handlers {
		mux.Handle(pattern, handler)
	}
	return mux, nil
}
