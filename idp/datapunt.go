package idp

import (
	"errors"
	"net/http"
	"net/url"
)

// An IdP implementation of the Datapunt IdP.
type DatapuntIdP struct {
	BaseURL string
}

// Constructor. Validating its config and creates the instance.
func NewDatapuntIdP(config interface{}) (*DatapuntIdP, error) {
	if dpConfig, ok := config.(map[string]interface{}); ok {
		if baseUrl, ok := dpConfig["url"].(string); ok {
			return &DatapuntIdP{baseUrl}, nil
		}
	}
	return nil, errors.New("Invalid Datapunt IdP configuration")
}

// Generate the Authentication redirect.
func (d *DatapuntIdP) AuthnRedirect(callbackURL url.URL, opaqueToken string) (redirURL url.URL, key []byte, value []byte) {
	return
}

// Get the user attributes.
func (d *DatapuntIdP) UserAttributes(r *http.Request) (uAttrs []byte, err error) {
	return
}
