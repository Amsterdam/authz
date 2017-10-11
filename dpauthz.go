package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/amsterdam/authz/oauth2"
	log "github.com/sirupsen/logrus"
)

type authzHalObject struct {
	Embedded authzHalEmbedded    `json:"_embedded"`
	Etag     string              `json:"_etag"`
	Links    authzHalLinksObject `json:"_links"`
}

type authzHalEmbedded struct {
	Item []authzHalObject `json:"item"`
}

type authzHalLinksObject struct {
	Self        interface{}        `json:"self"`
	DescribedBy interface{}        `json:"described_by"`
	Item        []authzHalLinkItem `json:"item"`
	Role        []authzHalLinkItem `json:"role"`
	Scope       []authzHalLinkItem `json:"scope"`
}

type authzHalLinkItem struct {
	Href  string `json:"href"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

type datapuntScopeSet map[string]struct{}

func (s datapuntScopeSet) ValidScope(scope ...string) bool {
	for _, scp := range scope {
		if _, ok := s[scp]; !ok {
			return false
		}
	}
	return true
}

type datapuntAuthz struct {
	allScopes      datapuntScopeSet
	scopeLock      sync.RWMutex
	roleLock       sync.RWMutex
	roleMap        map[string][]string
	setURL         string
	etag           string
	client         http.Client
	updateInterval int
}

func newDatapuntAuthz(conf *authzConfig) (*datapuntAuthz, error) {
	var setURL *url.URL
	baseURL, err := url.Parse(conf.BaseURL)
	if err != nil {
		return nil, err
	}
	if setURL, err = baseURL.Parse("profiles"); err != nil {
		return nil, err
	}
	query := setURL.Query()
	query.Set("embed", "item")
	setURL.RawQuery = query.Encode()
	provider := &datapuntAuthz{
		allScopes:      make(datapuntScopeSet),
		setURL:         setURL.String(),
		client:         http.Client{Timeout: 850 * time.Millisecond},
		updateInterval: conf.UpdateInterval,
	}
	if err := provider.runUpdate(); err != nil {
		return nil, err
	}
	go provider.updater()
	log.Infoln("Created datapunt scopeset")
	return provider, nil
}

func (s *datapuntAuthz) ValidScope(scope ...string) bool {
	s.scopeLock.RLock()
	defer s.scopeLock.RUnlock()
	return s.allScopes.ValidScope(scope...)
}

func (s *datapuntAuthz) ScopeSetFor(u *oauth2.User) (oauth2.ScopeSet, error) {
	scopeSet := make(datapuntScopeSet)
	s.roleLock.RLock()
	defer s.roleLock.RUnlock()
	roles, ok := u.Data.([]string)
	if !ok {
		return nil, errors.New("Invalid user data")
	}
	for _, role := range roles {
		for _, scope := range s.roleMap[role] {
			scopeSet[scope] = struct{}{}
		}
	}
	return scopeSet, nil
}

func (s *datapuntAuthz) updater() {
	for range time.Tick(time.Duration(s.updateInterval) * time.Second) {
		if err := s.runUpdate(); err != nil {
			log.WithError(err).Errorln("Couldn't update scope map")
		}
	}
}

func (s *datapuntAuthz) runUpdate() error {
	log.Infoln("Updating Datapunt authorization")
	req, err := http.NewRequest("GET", s.setURL, nil)
	if err != nil {
		return err
	}
	if s.etag != "" {
		req.Header.Set("If-None-Match", s.etag)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 304 {
		log.Infoln("Datapunt authorization has not changed")
		return nil
	}
	if resp.StatusCode != 200 {
		log.Warnf("unexpected response from Datapunt authz: %s\n", resp.Status)
		return nil
	}
	var (
		data    authzHalObject
		roleMap = make(map[string][]string)
		scopes  = make(map[string]struct{})
	)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		return err
	}
	// Parse: _embedded -> item[i] -> _links -> item[j] -> name
	for _, embeddedItem := range data.Embedded.Item {
		for _, role := range embeddedItem.Links.Role {
			for _, scope := range embeddedItem.Links.Scope {
				scopes[scope.Name] = struct{}{}
				roleMap[role.Name] = append(roleMap[role.Name], scope.Name)
			}
		}
	}
	s.scopeLock.Lock()
	s.allScopes = scopes
	s.scopeLock.Unlock()
	s.roleLock.Lock()
	s.roleMap = roleMap
	s.roleLock.Unlock()
	s.etag = resp.Header.Get("ETag")
	log.Infoln("Updated Datapunt scope set")
	return nil
}
