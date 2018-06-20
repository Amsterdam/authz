// An IdP implementation of Google OIC: https://developers.google.com/identity/protocols/OpenIDConnect
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amsterdam/authz/oauth2"
)

var (
	googleAuthURL      = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL     = "https://www.googleapis.com/oauth2/v4/token"
	googleAuthScope    = "openid email"
	googleResponseType = "code"
	googleGrantType    = "authorization_code"
)

type googleIDPResponseData struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
}

type googleIDToken struct {
	Issuer              string `json:"iss"`
	AccessTokenHash     string `json:"at_hash"`
	EmailIsVerified     bool   `json:"email_verified"`
	Subject             string `json:"sub"`
	AuthorizedPresenter string `json:"azp"`
	Email               string `json:"email"`
	ProfileURL          string `json:"profile"`
	PictureURL          string `json:"picture"`
	Name                string `json:"name"`
	Audience            string `json:"aud"`
	IssuedAt            int    `json:"iat"`
	ExpiryTime          int    `json:"exp"`
	Nonce               string `json:"nonce"`
}

type googleIDP struct {
	clientID     string
	clientSecret string
	oauthBaseURL string
	roles        *datapuntRoles
	client       *http.Client
}

// Constructor. Validating its config and creates the instance.
func newGoogleIDP(clientID string, clientSecret string, oauthBaseURL string, roles *datapuntRoles) *googleIDP {
	return &googleIDP{
		clientID, clientSecret, oauthBaseURL, roles, &http.Client{Timeout: 1 * time.Second},
	}
}

// ID returns "google-oic"
func (g *googleIDP) ID() string {
	return "google-oic"
}

func (g *googleIDP) oauth2CallbackURL() string {
	return g.oauthBaseURL + "oauth2/callback/" + g.ID()
}

// AuthnRedirect generates the Authentication redirect.
func (g *googleIDP) AuthnRedirect(authzRef string) (*url.URL, error) {
	// Build URL
	authURL, err := url.Parse(googleAuthURL)
	if err != nil {
		return nil, err
	}
	authQuery := authURL.Query()
	authQuery.Set("client_id", g.clientID)
	authQuery.Set("response_type", "code")
	authQuery.Set("scope", "openid email")
	authQuery.Set("redirect_uri", g.oauth2CallbackURL())
	authQuery.Set("state", authzRef)
	authURL.RawQuery = authQuery.Encode()
	return authURL, nil
}

// User returns a User and the original opaque token.
func (g *googleIDP) AuthnCallback(r *http.Request) (string, *oauth2.User, error) {
	// Parse request
	q := r.URL.Query()
	// Get authzRef
	state, ok := q["state"]
	if !ok {
		return "", nil, nil
	}
	authzRef := state[0]
	// Get code
	authzCode, ok := q["code"]
	if !ok {
		return authzRef, nil, nil
	}
	// Build request parameters
	data := url.Values{}
	data.Set("code", authzCode[0])
	data.Set("client_id", g.clientID)
	data.Set("client_secret", g.clientSecret)
	data.Set("redirect_uri", g.oauth2CallbackURL())
	data.Set("grant_type", googleGrantType)
	// Get token
	resp, err := g.client.PostForm(googleTokenURL, data)
	if err != nil {
		return "", nil, err
	}
	// Parse response
	if resp.StatusCode != 200 {
		return authzRef, nil, nil
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	var authData googleIDPResponseData
	if err := json.Unmarshal(buf.Bytes(), &authData); err != nil {
		return authzRef, nil, nil
	}
	// split the id token
	parts := strings.Split(authData.IDToken, ".")
	if len(parts) != 3 {
		return authzRef, nil, nil
	}
	b64IDToken := parts[1]
	// decode the payload
	rawIDToken, err := base64.RawURLEncoding.DecodeString(b64IDToken)
	if err != nil {
		return authzRef, nil, nil
	}
	var idToken googleIDToken
	if err := json.Unmarshal(rawIDToken, &idToken); err != nil {
		fmt.Println(err)
		return authzRef, nil, nil
	}
	// Get roles
	roles, err := g.roles.Get(idToken.Email)
	if err != nil {
		return authzRef, nil, nil
	}
	return authzRef, &oauth2.User{UID: idToken.Subject, Data: roles}, nil

}
