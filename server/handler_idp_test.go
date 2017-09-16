package server

import (
	"net/url"
	"testing"
)

var idProviderHandler *idpHandler

func init() {
	baseURL, _ := url.Parse("http://testserver/idp")

	idProviderHandler = &idpHandler{baseHandler(), testIdProvider(), baseURL, accessTokenEnc()}
}

type testAuthzState struct {
	*authorizationState
}

func (s *testAuthzState) Do() error {
	token := "test"
	store := idProviderHandler.stateStore
	if err := store.persist(token, s.authorizationState); err != nil {
		return err
	}
	return nil
}

func TestIdPHandler(t *testing.T) {
}
