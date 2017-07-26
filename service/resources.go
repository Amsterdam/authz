package service

import "net/http"

type OAuth2 struct {
	Handler *Handler
	// IdPRegistry IdPRegistry
	// ClientRegistry ClientRegistry
	// ScopesMap ScopeMap
}

func NewOAuth2() *OAuth2 {
	oauth2 := &OAuth2{
		Handler: NewHandler(),
	}

	oauth2.Handler.addResources(
		Resource{
			"authorizationrequest", "/authorize",
			methodHandler{
				"GET": oauth2.authorizationRequest,
			},
		},
	)
	return oauth2
}

// authorizationRequest handles an OAuth 2.0 authorization request
func (h *OAuth2) authorizationRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
