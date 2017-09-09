package server

import (
	"errors"
	"time"
)

type transientMap map[string]*struct {
	string
	time.Time
}

func (s transientMap) Set(key string, value string, expireIn int) error {
	exp := time.Now().Add(time.Duration(expireIn) * time.Second)
	s[key] = &struct {
		string
		time.Time
	}{value, exp}
	return nil
}

func (s transientMap) Get(key string) (string, error) {
	if res, ok := s[key]; ok {
		if res.Time.After(time.Now()) {
			return res.string, nil
		}
	}
	return "", errors.New("key not found in map")
}
