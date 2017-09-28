package oauth20

import (
	"encoding/base64"
	"log"
	"math/rand"
	"net/http"
	"net/url"
)

func (h *oauth20Handler) serveIdPCallback(w http.ResponseWriter, r *http.Request) {
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
	idp, ok := h.idps[state.IdPID]
	if !ok {
		log.Printf("Error finding IdP: %s\n", state.IdPID)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	user, err := idp.User(r, state.IdPState)
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
	accessToken, err := h.accessTokenEnc.Encode(user.UID, grantedScopes)
	if err != nil {
		log.Println(err)
		h.errorResponse(w, redirectURI, "server_error", "internal server error")
		return
	}
	h.implicitResponse(
		w, redirectURI, accessToken, "bearer", h.accessTokenEnc.Lifetime(),
		grantedScopes, state.State,
	)
}

type authnSession struct {
	Token    string
	Redir    string
	IdPState []byte
}

// createSession saves the current state of the authorization request and
// returns a redirect URL for the given idp
func (h *oauth20Handler) createSession(idp IdP, state *authorizationState) (string, error) {
	// Create token
	token := make([]byte, 16)
	rand.Read(token)
	b64Token := base64.RawURLEncoding.EncodeToString(token)
	// Add token to callback URL
	query := url.Values{}
	query.Set("token", b64Token)
	callbackURL := h.callbackURL
	callbackURL.RawQuery = query.Encode()
	// Het authentication redirect
	redir, idpState, err := idp.AuthnRedirect(&callbackURL)
	if err != nil {
		return "", err
	}
	state.IdPState = idpState
	if err := h.stateStore.persist(b64Token, state); err != nil {
		return "", err
	}
	return redir.String(), nil
}
