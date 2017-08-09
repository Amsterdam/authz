// Identity provider interface and implementations.

package idp

import (
	"net/http"
	"net/url"
)

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns a URL and optionally, a key and value that
	// will be stored for future retrieval.
	AuthnRedirect(callbackURL url.URL, opaqueToken string) (url.URL, []byte, []byte)

	// UserAttributes returns attributes as a json string in a byte slice.
	UserAttributes(r *http.Request) ([]byte, error)
}

func IdPMap() map[string]IdP {
	return map[string]IdP{
		"datapunt": DatapuntIdP{""},
	}
}

type DatapuntIdP struct {
	BaseURL string
}

func (d DatapuntIdP) AuthnRedirect(callbackURL url.URL, opaqueToken string) (redirURL url.URL, key []byte, value []byte) {
	return
}

func (d DatapuntIdP) UserAttributes(r *http.Request) (uAttrs []byte, err error) {
	return
}
