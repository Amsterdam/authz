package storage

import (
	"errors"
	"time"
)

type InMemoryValue struct {
	value    string
	expireAt time.Time
}

type InMemoryStorage map[string]*InMemoryValue

func (s InMemoryStorage) Set(key string, value string, expireIn int) error {
	exp := time.Now().Add(time.Duration(expireIn) * time.Second)
	s[key] = &InMemoryValue{value, exp}
	return nil
}

func (s InMemoryStorage) Get(key string) (string, error) {
	if res, ok := s[key]; ok {
		if res.expireAt.After(time.Now()) {
			return res.value, nil
		}
	}
	return "", errors.New("key not found in map")
}
