package idp

import (
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/rfc6749/transientstorage"
)

// User wraps all information we want an IdP to return to us.
type User struct {
	UId   string
	Roles []string
}

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns an authentication URL.
	AuthnRedirect(opaqueToken string, callbackURL url.URL, kv transientstorage.TransientStorageIdP) (string, error)

	// User returns the User and opaque token.
	User(r *http.Request, kv transientstorage.TransientStorageIdP) (*User, string, error)
}

type IdPMap interface {
	Get(idpId string) (IdP, error)
}
