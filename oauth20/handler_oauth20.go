package oauth20

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// baseHandler is the base handler for all OAuth 2.0 request handlers
type baseHandler struct {
	clients    ClientMap
	authz      Authz
	stateStore *stateStorage
}

// oauth20Error
func (h *baseHandler) errorResponse(
	w http.ResponseWriter, r *url.URL, code string, desc string) {
	query := r.Query()
	query.Set("error", code)
	query.Set("error_description", desc)
	r.RawQuery = query.Encode()
	headers := w.Header()
	headers.Add("Location", r.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h *baseHandler) implicitResponse(
	w http.ResponseWriter, redirectURI *url.URL, accessToken string,
	tokenType string, lifetime int64, scope []string, state string) {
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
