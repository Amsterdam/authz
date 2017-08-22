package idp

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/DatapuntAmsterdam/goauth2/rfc6749/transientstorage"
)

// An IdP implementation of the Datapunt IdP.
type DatapuntIdP struct {
	baseURL string
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
func (d *DatapuntIdP) AuthnRedirect(opaqueToken string, callbackURL url.URL, kv transientstorage.TransientStorageIdP) (string, error) {
	cbQuery := callbackURL.Query()
	cbQuery.Set("token", opaqueToken)
	callbackURL.RawQuery = cbQuery.Encode()
	callbackURL.Fragment = "#"

	baseURL, err := url.Parse(d.baseURL)
	if err != nil {
		return "", err
	}
	buQuery := baseURL.Query()
	buQuery.Set("callback", callbackURL.String())
	baseURL.RawQuery = buQuery.Encode()

	return baseURL.String(), nil
}

// User returns a User and the original opaque token.
func (d *DatapuntIdP) User(r *http.Request, kv transientstorage.TransientStorageIdP) (*User, string, error) {
	return nil, "", nil
}
