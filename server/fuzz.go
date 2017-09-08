// +build gofuzz

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/DatapuntAmsterdam/goauth2/authz"
	"github.com/DatapuntAmsterdam/goauth2/client"
)

type ClientMap struct {
	data *client.OAuth20ClientData
}

func (c *ClientMap) Get(id string) (*client.OAuth20ClientData, error) {
	return c.data, nil
}

type AuthzProvider struct{}

func (p *AuthzProvider) ValidScope(scope ...string) bool {
	return true
}

func (p *AuthzProvider) ScopeSetFor(u *authz.User) authz.ScopeSet {
	return p
}

func Fuzz(data []byte) (result int) {
	// Defer crashrecovery for invalid httptest.Requests
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(string); ok {
				if strings.Contains(err, "invalid NewRequest arguments") {
					result = -1
				}
			}
		}
	}()
	// Create all components
	clientMap := &ClientMap{
		data: &client.OAuth20ClientData{
			Id:        "implicitclient",
			Redirects: []string{"http://localhost/"},
			GrantType: "token",
		},
	}
	authnRedirects := map[string]AuthnRedirect{
		"testidp": func(state *AuthorizationState) (*url.URL, error) {
			return url.Parse("http://localhost/")
		},
	}
	authzProvider := &AuthzProvider{}
	// Create request
	req := httptest.NewRequest("GET", "/authorize", http.NoBody)
	req.URL.RawQuery = string(data)
	request := &AuthorizationRequest{
		Request:        req,
		clients:        clientMap,
		authnRedirects: authnRedirects,
		authzProvider:  authzProvider,
	}

	if c, err := request.ClientId(); err != nil {
		if c != "" {
			panic("ClientID not empy after error")
		}
		return 0
	}
	redir, err := request.RedirectURI()
	if err != nil {
		if redir != "" {
			panic("RedirectURI not empty after error")
		}
		return 0
	}
	_, err = url.Parse(redir)
	if err != nil {
		panic("Invalid redirect uri in test")
	}
	if r, err := request.ResponseType(); err != nil {
		if r != "" {
			panic("ResponseType not empty after error")
		}
		if _, ok := err.(*OAuth20Error); ok {
			return 0
		}
		panic(fmt.Sprintf("Unexpected error while checking responsetype: %s", err))
	}
	request.State()
	if s, err := request.Scope(); err != nil {
		if s != nil {
			panic("Scope not empty after error")
		}
		if _, ok := err.(*OAuth20Error); ok {
			return 0
		}
		panic(fmt.Sprintf("Unexpected error while checking scope: %s", err))
	}
	if _, err := request.AuthnRedirect(); err != nil {
		panic(fmt.Sprintf("Couldnt get redirect function: %s", err))
	}
	return 1
}
