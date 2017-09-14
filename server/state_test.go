package server

import (
	"fmt"
	"reflect"
	"testing"
)

func TestState(t *testing.T) {
	state := &authorizationState{
		ClientId:     "client",
		RedirectURI:  "http://redirect",
		ResponseType: "token",
		Scope:        []string{"abc", "def"},
		State:        "abcstate",
		IdPData:      []byte("the idp set me"),
	}
	marshalled, err := marshallAuthorizationState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshallAuthorizationState(marshalled)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, state) {
		t.Fatal(fmt.Errorf("Decoded != state: (%s, %s)", decoded, state))
	}
	if _, err := unmarshallAuthorizationState("badstate"); err == nil {
		t.Fatal("Shouldn't be able to unmarshall bad state")
	}
}
