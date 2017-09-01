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

	"github.com/DatapuntAmsterdam/goauth2/authz"
)

// Map stores IdP instances indexed by IdP id.
type Map map[string]IdP

// Config stores configuration indexed by idp_id.
type Config map[string]interface{}

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns an authentication URL and optional serialized data.
	AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error)

	// User receives the IdP's callback request and returns a User object or an error.
	User(r *http.Request) (*authz.User, error)
}

// Load returns a map of IdP-id -> IdP.
func Load(config Config) (map[string]IdP, error) {
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
		default:
			log.Printf("WARNING: Unknown IdP in config: %s\n", idp)
		}
	}
	// Add anonymous IdP only if no other IdP's are loaded
	if len(cache) == 0 {
		cache["anonymous"] = &AnonymousIdP{}
		log.Println("WARNING: Added Anonymous IdP")
	}
	return cache, nil
}
