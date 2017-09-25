package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/amsterdam/goauth2/oauth20"
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
	allScopes datapuntScopeSet
	scopeLock sync.RWMutex
	roleLock  sync.RWMutex
	roleMap   map[string][]string
	ticker    *time.Ticker
	setURL    string
	etag      string
	client    http.Client
}

func newDatapuntAuthz(u string) (*datapuntAuthz, error) {
	var setURL *url.URL
	if baseURL, err := url.Parse(u); err != nil {
		return nil, err
	} else {
		if setURL, err = baseURL.Parse("profiles"); err != nil {
			return nil, err
		}
		query := setURL.Query()
		query.Set("embed", "item")
		setURL.RawQuery = query.Encode()
	}
	provider := &datapuntAuthz{
		allScopes: make(datapuntScopeSet),
		ticker:    time.NewTicker(10 * time.Second),
		setURL:    setURL.String(),
		client:    http.Client{Timeout: 850 * time.Millisecond},
	}
	if err := provider.runUpdate(); err != nil {
		return nil, err
	}
	go provider.updater()
	log.Println("INFO: Created datapunt scopeset")
	return provider, nil
}

func (s *datapuntAuthz) ValidScope(scope ...string) bool {
	s.scopeLock.RLock()
	defer s.scopeLock.RUnlock()
	return s.allScopes.ValidScope(scope...)
}

func (s *datapuntAuthz) ScopeSetFor(u *oauth20.User) oauth20.ScopeSet {
	scopeSet := make(datapuntScopeSet)
	s.roleLock.RLock()
	defer s.roleLock.RUnlock()
	for _, role := range u.Roles {
		for _, scope := range s.roleMap[role] {
			scopeSet[scope] = struct{}{}
		}
	}
	return scopeSet
}

func (s *datapuntAuthz) updater() {
	for {
		select {
		case <-s.ticker.C:
			if err := s.runUpdate(); err != nil {
				log.Println("ERROR: while updating scope map: %s", err)
			}
		}
	}
	log.Printf("INFO: Stopped datapunt scopeset updater")
}

func (s *datapuntAuthz) runUpdate() error {
	log.Println("INFO: Updating Datapunt authorization")
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
		log.Println("INFO: Datapunt authorization has not changed")
		return nil
	}
	if resp.StatusCode != 200 {
		log.Printf("WARN: %s response from Datapunt authz: %s\n", resp.Status)
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
	log.Println("INFO: Updated Datapunt scope set")
	return nil
}
