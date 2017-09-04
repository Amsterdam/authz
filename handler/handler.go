package handler

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/authz"
	"github.com/DatapuntAmsterdam/goauth2/client"
	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

func NewOAuth20Handler(baseURL *url.URL, clients client.OAuth20ClientMap, idps idp.Map, authzProvider authz.Provider, accesstokenEncoder *AccessTokenEncoder, store storage.Transient) (http.Handler, error) {
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
		handler := &IdPHandler{idp, store, u, authzProvider, accesstokenEncoder}
		authnRedirects[idpId] = handler.AuthnRedirect
		handlers[fmt.Sprintf("/%s", relPath)] = handler
	}
	// Create authorization handler
	authzHandler := &AuthorizationHandler{clients, authnRedirects, authzProvider}
	handlers["/authorize"] = authzHandler
	// Create mux handler and register handlers
	mux := http.NewServeMux()
	for pattern, handler := range handlers {
		mux.Handle(pattern, handler)
	}
	return mux, nil
}
