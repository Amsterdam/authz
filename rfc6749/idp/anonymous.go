package idp

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/rfc6749/transientstorage"
)

type AnonymousIdP struct{}

func (a *AnonymousIdP) AuthnRedirect(opaqueToken string, callbackURL url.URL, kv transientstorage.TransientStorageIdP) (url.URL, error) {
	query := callbackURL.Query()
	query.Set("token", opaqueToken)
	callbackURL.RawQuery = query.Encode()
	return callbackURL, nil
}

// User returns a User and the original opaque token.
func (a *AnonymousIdP) User(r *http.Request, kv transientstorage.TransientStorageIdP) (*User, string, error) {
	if token, ok := r.URL.Query()["token"]; ok {
		return &User{"Anonymous", []string{}}, token[0], nil
	}
	return nil, "", errors.New("No token supplied")
}
