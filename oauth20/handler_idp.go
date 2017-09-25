package oauth20

import (
	"encoding/base64"
	"log"
	"math/rand"
	"net/http"
	"net/url"
)

type idpHandler struct {
	*baseHandler
	IdP
	baseURL      *url.URL
	tokenEncoder *accessTokenEncoder
}

func (h *idpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("token parameter missing."))
		return
	}
	var state authorizationState
	if err := h.stateStore.restore(token[0], &state); err != nil {
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
	user, err := h.User(r, state.IdPState)
	if err != nil {
		log.Printf("Error authenticating user: %s\n", err)
		h.errorResponse(w, redirectURI, "access_denied", "couldn't authenticate user")
		return
	}
	grantedScopes := []string{}
	if len(state.Scope) > 0 {
		userScopes := h.authz.ScopeSetFor(user)
		for _, scope := range state.Scope {
			if userScopes.ValidScope(scope) {
				grantedScopes = append(grantedScopes, scope)
			}
		}
	}
	accessToken, err := h.tokenEncoder.Encode(user.UID, grantedScopes)
	if err != nil {
		log.Println(err)
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}
	h.implicitResponse(w, redirectURI, accessToken, "bearer", h.tokenEncoder.Lifetime(), grantedScopes, state.State)
}

type authnSession struct {
	Token    string
	Redir    string
	IdPState []byte
}

func (h *idpHandler) newAuthnSession() (*authnSession, error) {
	token := make([]byte, 16)
	rand.Read(token)
	b64token := base64.RawURLEncoding.EncodeToString(token)
	callback := *h.baseURL
	query := callback.Query()
	query.Set("token", b64token)
	callback.RawQuery = query.Encode()
	redir, idpState, err := h.AuthnRedirect(&callback)
	if err != nil {
		return nil, err
	}
	return &authnSession{
		Token:    b64token,
		Redir:    redir.String(),
		IdPState: idpState,
	}, nil
}
