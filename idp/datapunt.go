package idp

import (
	"errors"
	"net/http"
	"net/url"
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
func (d *DatapuntIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	var (
		baseURL *url.URL
		err     error
	)
	callbackURL.Fragment = "#"

	baseURL, err = url.Parse(d.baseURL)
	if err != nil {
		return baseURL, nil, err
	}
	buQuery := baseURL.Query()
	buQuery.Set("callback", callbackURL.String())
	baseURL.RawQuery = buQuery.Encode()

	return baseURL, nil, nil
}

// User returns a User and the original opaque token.
func (d *DatapuntIdP) User(r *http.Request) (*User, error) {
	return nil, nil
}
