package server

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
)

// Characters used for random tokens.
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type idpHandler struct {
	Authn
	stateStore   *stateStorage
	baseURL      *url.URL
	authz        Authz
	tokenEncoder *accessTokenEncoder
}

func (i *idpHandler) implicitResponse(w http.ResponseWriter, redirectURI url.URL, accessToken string, tokenType string, lifetime int, scope []string, state string) {
	v := url.Values{}
	v.Set("access_token", accessToken)
	v.Set("token_type", tokenType)
	v.Set("expires_in", fmt.Sprintf("%d", lifetime))
	v.Set("scope", strings.Join(scope, " "))
	if len(state) > 0 {
		v.Set("state", state)
	}
	redirectURI.Fragment = v.Encode()
	w.Header().Add("Location", redirectURI.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (i *idpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("make an authorization request first."))
		return
	}
	var state authorizationState
	if err := i.stateStore.restore(token[0], &state); err != nil {
		log.Printf("Error restoring state token: %s\n", err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid state token."))
		return
	}
	redirectURI, err := url.Parse(state.RedirectURI)
	if err != nil {
		log.Printf("Error reconstructing redirect_uri from unmarshalled state: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := i.User(r, state.IdPData)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userScopes := i.authz.ScopeSetFor(user)
	var grantedScopes []string
	for _, scope := range state.Scope {
		if userScopes.ValidScope(scope) {
			grantedScopes = append(grantedScopes, scope)
		}
	}
	accessToken, err := i.tokenEncoder.Encode(user.UID, grantedScopes)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	i.implicitResponse(w, *redirectURI, accessToken, "bearer", 3600*10, grantedScopes, state.State)
}

func (i *idpHandler) url(state *authorizationState) (*url.URL, error) {
	token := make([]byte, 16)
	for i := range token {
		token[i] = letters[rand.Int63()%int64(len(letters))]
	}
	key := string(token)
	baseURL := i.baseURL
	query := baseURL.Query()
	query.Set("token", key)
	baseURL.RawQuery = query.Encode()
	redir, idpData, err := i.AuthnRedirect(baseURL)
	if err != nil {
		return nil, err
	}
	state.IdPData = idpData
	if err := i.stateStore.persist(key, state); err != nil {
		return nil, err
	}
	return redir, nil
}
