/*
Package idp provides identity provider interfaces and implementations.

This package holds:

1. Definitions of the IdP interface and User type.
2. Implementations of IdP for specific identity providers.
3. A Loader that returns a map of IdP-id -> IdP object.

TODO: consider using reflection in Load, or alternatively https://golang.org/pkg/plugin/
*/
package idp

import (
	"log"
	"net/http"
	"net/url"
)

// IdPMap stores IdP instances indexed by IdP id.
type IdPMap map[string]IdP

// IdPConfig stores configuration indexed by idp_id.
type IdPConfig map[string]interface{}

// User wraps all information we want an IdP to return to us.
type User struct {
	UId   string
	Roles []string
}

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns an authentication URL and optional serialized data.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)

	// User receives the IdP's callback request and returns a User object or an error.
	User(r *http.Request) (*User, error)
}

// Load returns a map of IdP-id -> IdP.
func Load(config IdPConfig) (map[string]IdP, error) {
	cache := make(map[string]IdP)
	var err error
	for idp, idpConfig := range config {
		switch idp {
		case "datapunt":
			cache[idp], err = NewDatapuntIdP(idpConfig)
			if err != nil {
				return nil, err
			}
			log.Println("Added Datapunt IdP")
		case "anonymous":
			cache[idp] = &AnonymousIdP{}
			log.Println("Added Anonymous IdP")
		default:
			log.Printf("WARNING: Unknown IdP in config: %s\n", idp)
		}
	}
	return cache, nil
}
