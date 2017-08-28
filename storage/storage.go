package storage

import (
	"errors"
	"log"
)

type TransientConfig map[string]interface{}

type Transient interface {
	Set(key string, value string, expireIn int) error
	Get(key string) (string, error)
}

func Load(config TransientConfig) (Transient, error) {
	if len(config) > 1 {
		return nil, errors.New("Only one storage back-end may be enabled at once")
	}
	for store, storeConfig := range config {
		switch store {
		case "redis":
			return NewRedisStorage(storeConfig)
		default:
			log.Printf("WARNING: ignoring unknown storage type: %s\n", store)
		}
	}
	log.Println("Using in-memory storage")
	return make(InMemoryStorage), nil
}
