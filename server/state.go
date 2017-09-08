package server

import (
	"bytes"
	"encoding/gob"
)

type authorizationState struct {
	ClientId     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
	IdPData      []byte
}

func unmarshallAuthorizationState(encoded string) (*authorizationState, error) {
	var state authorizationState
	data := bytes.NewBufferString(encoded)
	dec := gob.NewDecoder(data)
	if err := dec.Decode(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func marshallAuthorizationState(s *authorizationState) (string, error) {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return data.String(), nil
}
