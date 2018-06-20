package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type authnHalAccount struct {
	Etag  string        `json:"_etag"`
	Links authnHalLinks `json:"_links"`
}

type authnHalLinks struct {
	Self  authnHalLinkItem   `json:"self"`
	Roles []authnHalLinkItem `json:"role"`
}

type authnHalLinkItem struct {
	HREF  string `json:"href"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

type datapuntRoles struct {
	accountsURL *url.URL
	apiKey      string
	client      *http.Client
}

func newDatapuntRoles(accountsURL string, apiKey string) (*datapuntRoles, error) {
	url, err := url.Parse(accountsURL)
	if err != nil {
		return nil, errors.New("Invalid accounts URL for Datapunt IdP")
	}
	client := &http.Client{Timeout: 1 * time.Second}
	return &datapuntRoles{url, apiKey, client}, nil
}

func (d *datapuntRoles) Get(uid string) ([]string, error) {
	accountURL, err := d.accountsURL.Parse(uid)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("GET", accountURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("apikey %s", d.apiKey))
	resp, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("Unexpected response code from Datapunt IdP when requesting roles: %s\n", resp.Status)
		return nil, errors.New(msg)
	}
	var account authnHalAccount
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&account); err != nil {
		return nil, err
	}
	// Create User
	var roles []string
	for _, role := range account.Links.Roles {
		roles = append(roles, role.Name)
	}
	return roles, nil
}
