package server

import "errors"

// emptyClientMap contains no clients
type emptyClientMap struct{}

// emptyClientMap contains no clients
func (m *emptyClientMap) Get(id string) (*Client, error) {
	return nil, errors.New("Unknown client id")
}
