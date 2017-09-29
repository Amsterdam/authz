package oauth20

import (
	"fmt"
	"sync"
	"time"
)

type stateMap struct {
	values   map[string]string
	expiries map[string]time.Time
	mutex    sync.Mutex
}

func newStateMap() *stateMap {
	return &stateMap{
		values:   make(map[string]string),
		expiries: make(map[string]time.Time),
	}
}

func (s *stateMap) Persist(key string, value string, lifetime time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	exp := time.Now().Add(lifetime)
	s.values[key] = value
	s.expiries[key] = exp
	return nil
}

func (s *stateMap) Restore(key string) (string, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	val, valOk := s.values[key]
	exp, expOk := s.expiries[key]
	if expOk {
		delete(s.expiries, key)
	}
	if valOk {
		delete(s.values, key)
	}
	if !valOk || !expOk || time.Now().After(exp) {
		return "", fmt.Errorf("key %s not found", key)
	}
	return val, nil
}
