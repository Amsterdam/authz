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
	pathTempl := "authorize/%s"
	for idpId, idp := range idps {
		relPath := fmt.Sprintf(pathTempl, idpId)
		u, err := baseURL.Parse(relPath)
		if err != nil {
			return nil, err
		}
		handler := &IdPHandler{idp, store, u}
		authnRedirects[idpId] = handler.AuthnRedirect
		handlers[fmt.Sprintf("/%s", relPath)] = handler
	}
	// Create authorization handler
	authzHandler := &AuthorizationHandler{clients, authnRedirects, scopes}
	handlers["/authorize"] = authzHandler
	// Create mux handler and register handlers
	mux := http.NewServeMux()
	for pattern, handler := range handlers {
		mux.Handle(pattern, handler)
	}
	return mux, nil
}
