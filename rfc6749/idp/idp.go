package idp

import (
	"log"
	"net/http"
	"net/url"
)

// User wraps all information we want an IdP to return to us.
type User struct {
	UId   string
	Roles []string
}

// The interface that needs to be implemented for identity providers.
type IdP interface {

	// AuthnRedirect(...) returns an authentication URL.
	AuthnRedirect(opaqueToken string, callbackURL url.URL, kv KeyValueStore) (string, error)

	// User returns the User and opaque token.
	User(r *http.Request, kv KeyValueStore) (*User, string, error)
}

// IdPConfig stores configuration indexed by idp_id.
type IdPConfig map[string]interface{}

// IdPMap returns a map with instances of all configured IdP's.
func IdPMap(config *IdPConfig) (map[string]IdP, error) {
	var err error
	idpMap := make(map[string]IdP)
	for idp, idpConfig := range *config {
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

type KeyValueStore interface {
	Get(key []byte) ([]byte, error)
	Set(key []byte, value []byte) error
}
