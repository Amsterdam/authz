package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/amsterdam/goauth2/oauth20"
)

type jwtHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type jwtPayload struct {
	IssuedAt  int    `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Subject   string `json:"sub"`
}

type authnHalAccount struct {
	Etag  string        `json:"_etag"`
	Links authnHalLinks `json:"_links"`
}

type authnHalLinks struct {
	Self  authnHalLinkItem   `json:"self"`
	Roles []authnHalLinkItem `json:"role"`
}

type authnHalLinkItem struct {
	HREF  string `json:"href"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

// An IdP implementation of the Datapunt IdP.
type datapuntIdP struct {
	baseURL     string
	accountsURL *url.URL
	secret      []byte
	apiKey      string
	client      *http.Client
}

// Constructor. Validating its config and creates the instance.
func newDatapuntIdP(
	baseURL string, accountsURL string, secret []byte,
	apiKey string) (*datapuntIdP, error) {
	if accURL, err := url.Parse(accountsURL); err != nil {
		return nil, errors.New("Invalid accounts URL for Datapunt IdP")
	} else {
		return &datapuntIdP{
			baseURL, accURL, secret, apiKey, &http.Client{Timeout: 1 * time.Second},
		}, nil
	}
}

// Generate the Authentication redirect.
func (d *datapuntIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
	var (
		baseURL *url.URL
		err     error
	)

	baseURL, err = url.Parse(d.baseURL)
	if err != nil {
		return nil, nil, err
	}
	buQuery := baseURL.Query()
	buQuery.Set("callback", callbackURL.String())
	baseURL.RawQuery = buQuery.Encode()

	return baseURL, nil, nil
}

// User returns a User and the original opaque token.
func (d *datapuntIdP) User(r *http.Request, state []byte) (*oauth20.User, error) {
	q := r.URL.Query()
	if token, ok := q["aselect_credentials"]; ok {
		tokenPayload, err := d.jwtPayload(token[0])
		if err != nil {
			return nil, err
		}
		return d.user(tokenPayload.Subject)
	}
	return nil, errors.New("Invalid reply")
}

func (d *datapuntIdP) jwtPayload(token string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		var (
			header  jwtHeader
			payload jwtPayload
		)
		b64header, b64payload, b64digest := parts[0], parts[1], parts[2]
		// Decode and verify the header
		if jsonHeader, err := base64.RawURLEncoding.DecodeString(b64header); err == nil {
			if err := json.Unmarshal(jsonHeader, &header); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
		if header.Algorithm != "HS256" {
			return nil, errors.New(fmt.Sprintf("Invalid credentials: unsupported algorithm %s", header.Algorithm))
		}
		if header.Type != "JWT" {
			return nil, errors.New(fmt.Sprintf("Invalid credentials: unsupported token type %s", header.Type))
		}
		// Decode and verify the signature
		signingInput := []byte(fmt.Sprintf("%v.%v", b64header, b64payload))
		if digest, err := base64.RawURLEncoding.DecodeString(b64digest); err == nil {
			mac := hmac.New(sha256.New, d.secret)
			mac.Write(signingInput)
			expectedMAC := mac.Sum(nil)
			if !hmac.Equal(digest, expectedMAC) {
				return nil, errors.New("Invalid credentials: checksum error")
			}
		}
		// Decode the payload
		if jsonPayload, err := base64.RawURLEncoding.DecodeString(b64payload); err == nil {
			if err := json.Unmarshal(jsonPayload, &payload); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
		// Verify the payload
		if time.Now().After(time.Unix(payload.ExpiresAt, 0)) {
			return nil, errors.New("Invalid credentials: expired")
		}
		return &payload, nil
	}
	return nil, errors.New("Invalid credentials: token doesn't have 3 parts")
}

func (d *datapuntIdP) user(uid string) (*oauth20.User, error) {
	accountURL, err := d.accountsURL.Parse(uid)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest("GET", accountURL.String(), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("apikey %s", d.apiKey))
	resp, err := d.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("Unexpected response code from Datapunt IdP when requesting roles: %s\n", resp.Status)
		return nil, errors.New(msg)
	}
	var account authnHalAccount
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&account); err != nil {
		return nil, err
	}
	// Create User
	var roles []string
	for _, role := range account.Links.Roles {
		roles = append(roles, role.Name)
	}
	return &oauth20.User{uid, roles}, nil
}
