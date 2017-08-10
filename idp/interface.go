// Identity provider interface and implementations.

package idp

import (
	"errors"
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

type DatapuntIdP struct {
	BaseURL string
}

func NewDatapuntIdP(config interface{}) (*DatapuntIdP, error) {
	if dpConfig, ok := config.(map[string]interface{}); ok {
		if baseUrl, ok := dpConfig["url"].(string); ok {
			return &DatapuntIdP{baseUrl}, nil
		}
	}
	return nil, errors.New("Invalid Datapunt IdP configuration")
}

func (d *DatapuntIdP) AuthnRedirect(callbackURL url.URL, opaqueToken string) (redirURL url.URL, key []byte, value []byte) {
	return
}

func (d *DatapuntIdP) UserAttributes(r *http.Request) (uAttrs []byte, err error) {
	return
}
