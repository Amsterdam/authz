package handler

import (
	"bytes"
	"encoding/gob"
)

type AuthorizationState struct {
	ClientId     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
	IdPData      []byte
}

func DecodeAuthorizationState(encoded string) (*AuthorizationState, error) {
	var state AuthorizationState
	data := bytes.NewBufferString(encoded)
	dec := gob.NewDecoder(data)
	if err := dec.Decode(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func (s *AuthorizationState) Encode() (string, error) {
	var data bytes.Buffer
	enc := gob.NewEncoder(&data)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return data.String(), nil
}
