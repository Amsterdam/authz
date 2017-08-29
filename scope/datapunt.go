package scope

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type DatapuntScopeSetHalObject struct {
	Embedded DatapuntScopeSetHalEmbedded    `json:"_embedded"`
	Etag     string                         `json:"_etag"`
	Links    DatapuntScopeSetHalLinksObject `json:"_links"`
}

type DatapuntScopeSetHalEmbedded struct {
	Item []DatapuntScopeSetHalObject `json:"item"`
}

type DatapuntScopeSetHalLinksObject struct {
	Self        interface{}                   `json:"self"`
	DescribedBy interface{}                   `json:"described_by"`
	Item        []DatapuntScopeSetHalLinkItem `json:"item"`
}

type DatapuntScopeSetHalLinkItem struct {
	Href  string `json:"href"`
	Name  string `json:"name"`
	Title string `json:"title"`
}
type DatapuntScopeSet struct {
	lock   sync.RWMutex
	ticker *time.Ticker
	exiter chan struct{}
	scopes map[string]struct{}
	setURL string
	etag   string
	client http.Client
}

func NewDatapuntScopeSet(config interface{}) (*DatapuntScopeSet, error) {
	var setURL *url.URL
	if scopeSetConfig, ok := config.(map[string]interface{}); ok {
		if baseURLConf, ok := scopeSetConfig["base-url"].(string); ok {
			if baseURL, err := url.Parse(baseURLConf); err != nil {
				return nil, err
			} else {
				if setURL, err = baseURL.Parse("datasets"); err != nil {
					return nil, err
				}
				query := setURL.Query()
				query.Set("embed", "item")
				setURL.RawQuery = query.Encode()
			}
			set := &DatapuntScopeSet{
				scopes: make(map[string]struct{}),
				ticker: time.NewTicker(10 * time.Second),
				exiter: make(chan struct{}),
				setURL: setURL.String(),
				client: http.Client{Timeout: 850 * time.Millisecond},
			}
			if err := set.runUpdate(); err != nil {
				return nil, err
			}
			go set.updater()
			log.Println("Created datapunt scopeset")
			return set, nil
		}
	}
	return nil, errors.New("Invalid configuration for Datapunt scope set")
}

func (s *DatapuntScopeSet) Includes(scope string) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, ok := s.scopes[scope]
	return ok
}

func (s *DatapuntScopeSet) updater() {
	for {
		select {
		case <-s.ticker.C:
			if err := s.runUpdate(); err != nil {
				log.Println("ERROR: while updating scope map: %s", err)
			}
		case <-s.exiter:
			break
		}
	}
	log.Printf("INFO: Stopped datapunt scopeset updater")
}

func (s *DatapuntScopeSet) runUpdate() error {
	log.Println("INFO: Updating Datapunt scope set")
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
		log.Println("INFO: Datapunt scope set has not changed")
		return nil
	}
	if resp.StatusCode != 200 {
		log.Printf("WARNING: Unexpected response code from Datapunt scope set URL: %s\n", resp.Status)
		return nil
	}
	var (
		data   DatapuntScopeSetHalObject
		scopes = make(map[string]struct{})
	)
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&data); err != nil {
		return err
	}
	// Parse: _embedded -> item[i] -> _links -> item[j] -> name
	for _, embeddedItem := range data.Embedded.Item {
		for _, link := range embeddedItem.Links.Item {
			scopes[link.Name] = struct{}{}
		}
	}
	s.lock.Lock()
	s.scopes = scopes
	s.lock.Unlock()
	s.etag = resp.Header.Get("ETag")
	log.Println("INFO: Updated Datapunt scope set")
	return nil
}

func (s *DatapuntScopeSet) Close() {
	close(s.exiter)
}
