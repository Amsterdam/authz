package oauth20

import (
	"bytes"
	"encoding/gob"
	"time"
)

type authorizationState struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
	IDPID        string
	IDPState     []byte
}

type stateStorage struct {
	engine      StateKeeper
	maxLifetime time.Duration
}

func newStateStorage(engine StateKeeper, lifetime time.Duration) *stateStorage {
	return &stateStorage{engine, lifetime}
}

func (store *stateStorage) restore(key string, e interface{}) error {
	encoded, err := store.engine.Restore(key)
	if err != nil {
		return err
	}
	data := bytes.NewBufferString(encoded)
	dec := gob.NewDecoder(data)
	return dec.Decode(e)
}

func (store *stateStorage) persist(key string, data interface{}) error {
	var encoded bytes.Buffer
	enc := gob.NewEncoder(&encoded)
	if err := enc.Encode(data); err != nil {
		return err
	}
	return store.engine.Persist(key, encoded.String(), store.maxLifetime)
}
