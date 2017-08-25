package handler

import (
	"log"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/idp"
	"github.com/DatapuntAmsterdam/goauth2/storage"
)

// Characters used for random tokens.
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type AuthnRedirect func(state *AuthorizationState) (*url.URL, error)

type IdPHandler struct {
	impl     idp.IdP
	store    storage.Transient
	callback *url.URL
}

func (i *IdPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		HTTP400BadRequest(w, "make an authorization request first.")
		return
	}
	data, err := i.store.Get(token[0])
	if err != nil {
		HTTP400BadRequest(w, "invalid state token.")
	}
	state, err := DecodeAuthorizationState(data)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := i.impl.User(r)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	log.Println(state, user)
	// Roles to scopes!
}

func (i *IdPHandler) AuthnRedirect(state *AuthorizationState) (*url.URL, error) {
	token := make([]byte, 16)
	for i := range token {
		token[i] = letters[rand.Int63()%int64(len(letters))]
	}
	key := string(token)
	callback := i.callback
	query := callback.Query()
	query.Set("token", key)
	callback.RawQuery = query.Encode()
	redir, idpData, err := i.impl.AuthnRedirect(callback)
	if err != nil {
		return nil, err
	}
	state.IdPData = idpData
	value, err := state.Encode()
	if err != nil {
		return nil, err
	}
	if err := i.store.Set(key, value, 600); err != nil {
		return nil, err
	}
	return redir, nil
}
