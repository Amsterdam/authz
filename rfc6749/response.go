package rfc6749

import (
	"net/http"
	"net/url"
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

func OAuth20IdPRedirect(w http.ResponseWriter) {
}
