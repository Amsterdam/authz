package handler

import (
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

type AuthnRedirect func(state *AuthorizationState, w http.ResponseWriter) (*url.URL, error)

type IdPHandler struct {
	funcs    idp.IdP
	store    storage.Transient
	callback *url.URL
}

func (i *IdPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//user, err := i.funcs.User(r)

}

func (i *IdPHandler) AuthnRedirect(state *AuthorizationState, w http.ResponseWriter) (*url.URL, error) {
	return nil, nil
}
