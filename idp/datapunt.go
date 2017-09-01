package idp

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

	"github.com/DatapuntAmsterdam/goauth2/authz"
)

type DatapuntJWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type DatapuntJWTPayload struct {
	IssuedAt  int    `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Subject   string `json:"sub"`
}

type DatapuntHalAccount struct {
	Etag  string           `json:"_etag"`
	Links DatapuntHalLinks `json:"_links"`
}

type DatapuntHalLinks struct {
	Self  DatapuntHalLinkItem   `json:"self"`
	Roles []DatapuntHalLinkItem `json:"role"`
}

type DatapuntHalLinkItem struct {
	HREF  string `json:"href"`
	Name  string `json:"name"`
	Title string `json:"title"`
}

// An IdP implementation of the Datapunt IdP.
type DatapuntIdP struct {
	baseURL     string
	accountsURL *url.URL
	secret      []byte
	client      *http.Client
}

// Constructor. Validating its config and creates the instance.
func NewDatapuntIdP(config interface{}) (*DatapuntIdP, error) {
	if dpConfig, ok := config.(map[string]interface{}); ok {
		var baseURL, secret string
		var accountsURL *url.URL
		if baseURL, ok = dpConfig["url"].(string); !ok {
			return nil, errors.New("Missing or invalid base URL in Datapunt IdP configuration")
		}
		if secret, ok = dpConfig["secret"].(string); !ok {
			return nil, errors.New("Missing or invalid secret in Datapunt IdP configuration")
		}
		if len(secret) <= 15 {
			return nil, errors.New("Secret in Datapunt IdP configuration must be at least 15 characters long")
		}
		if accountsURLstr, ok := dpConfig["accounts-url"].(string); ok {
			if u, err := url.Parse(accountsURLstr); err != nil {
				return nil, errors.New("Invalid accounts URL for Datapunt IdP")
			} else {
				accountsURL = u
			}
		} else {
			return nil, errors.New("Missing or invalid accounts URL in Datapunt IdP configuration")
		}
		return &DatapuntIdP{
			baseURL,
			accountsURL,
			[]byte(secret),
			&http.Client{Timeout: 1 * time.Second},
		}, nil
	}
	return nil, errors.New("Invalid Datapunt IdP configuration")
}

// Generate the Authentication redirect.
func (d *DatapuntIdP) AuthnRedirect(callbackURL *url.URL) (*url.URL, []byte, error) {
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
func (d *DatapuntIdP) User(r *http.Request, state []byte) (*authz.User, error) {
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

func (d *DatapuntIdP) jwtPayload(token string) (*DatapuntJWTPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		var (
			header  DatapuntJWTHeader
			payload DatapuntJWTPayload
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

func (d *DatapuntIdP) user(uid string) (*authz.User, error) {
	accountURL, err := d.accountsURL.Parse(uid)
	if err != nil {
		return nil, err
	}
	resp, err := d.client.Get(accountURL.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg := fmt.Sprintf("Unexpected response code from Datapunt IdP when requesting roles: %s\n", resp.Status)
		return nil, errors.New(msg)
	}
	var account DatapuntHalAccount
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&account); err != nil {
		return nil, err
	}
	// Create User
	u := &authz.User{Uid: uid}
	for _, role := range account.Links.Roles {
		u.Roles = append(u.Roles, role.Name)
	}
	return u, nil
}
