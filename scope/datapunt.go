package scope

import (
	"log"
	"sync"
	"time"
)

type DatapuntScopeSet struct {
	lock   sync.RWMutex
	ticker *time.Ticker
	exiter chan struct{}
	scopes map[string]struct{}
}

func NewDatapuntScopeSet() *DatapuntScopeSet {
	set := &DatapuntScopeSet{
		scopes: make(map[string]struct{}),
		ticker: time.NewTicker(10 * time.Second),
		exiter: make(chan struct{}),
	}
	go set.updater()
	log.Println("Created datapunt scopeset")
	return set
}

func (s *DatapuntScopeSet) Includes(scope string) bool {
	_, ok := s.scopes[scope]
	return ok
}

func (s *DatapuntScopeSet) updater() {
	for {
		select {
		case <-s.ticker.C:
			if err := s.runUpdate(); err != nil {
				log.Println("Error updating scope map: %s", err)
			}
		case <-s.exiter:
			break
		}
	}
	log.Printf("Stopped datapunt scopeset updater")
}

func (s *DatapuntScopeSet) runUpdate() error {
	log.Println("Updating scope map")
	return nil
}

func (s *DatapuntScopeSet) Close() {
	close(s.exiter)
}
