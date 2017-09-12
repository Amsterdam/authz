package server

import (
	"fmt"
	"sync"
	"time"
)

type transientMap struct {
	values   map[string]string
	expiries map[string]time.Time
	mutex    sync.Mutex
}

func newTransientMap() *transientMap {
	return &transientMap{
		values:   make(map[string]string),
		expiries: make(map[string]time.Time),
	}
}

func (s *transientMap) Set(key string, value string, expireIn int) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	exp := time.Now().Add(time.Duration(expireIn) * time.Second)
	s.values[key] = value
	s.expiries[key] = exp
	return nil
}

func (s *transientMap) GetAndRemove(key string) (result string, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	val, valOk := s.values[key]
	exp, expOk := s.expiries[key]
	if valOk && expOk && exp.After(time.Now()) {
		result = val
	} else {
		err = fmt.Errorf("key %s not found", key)
	}
	if expOk {
		delete(s.expiries, key)
	}
	if valOk {
		delete(s.values, key)
	}
	return val, err
}
