package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func HTTP400BadRequest(w http.ResponseWriter, body string) {
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(body))
}

func OAuth20ErrorResponse(w http.ResponseWriter, err *OAuth20Error, redirectURI *url.URL) {
	query := redirectURI.Query()
	query.Set("error", err.Code)
	query.Set("error_description", err.Description)
	redirectURI.RawQuery = query.Encode()
	headers := w.Header()
	headers.Add("Location", redirectURI.String())
	w.WriteHeader(http.StatusSeeOther)
}

func OAuth20ImplicitGrantAccessTokenResponse(w http.ResponseWriter, redirectURI url.URL, accessToken string, tokenType string, lifetime int, scope []string, state string) {
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

func OAuth20IdPRedirect(w http.ResponseWriter) {
}
