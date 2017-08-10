// Identity provider interface and implementations.

package idp

import (
	"log"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/config"
)

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns a URL and optionally, a key and value that
	// will be stored for future retrieval.
	AuthnRedirect(callbackURL url.URL, opaqueToken string) (url.URL, []byte, []byte)

	// UserAttributes returns attributes as a json string in a byte slice.
	UserAttributes(r *http.Request) ([]byte, error)
}

// IdPMap returns a map with instances of all configured IdP's.
func IdPMap(config *config.Config) (map[string]IdP, error) {
	var err error
	idpMap := make(map[string]IdP)
	for idp, idpConfig := range config.IdP {
		switch idp {
		case "datapunt":
			idpMap[idp], err = NewDatapuntIdP(idpConfig)
			if err != nil {
				return idpMap, err
			}
			log.Println("Added Datapunt IdP")
		default:
			log.Printf("WARNING: Unknown IdP in config: %s\n", idp)
		}
	}
	return idpMap, nil
}
