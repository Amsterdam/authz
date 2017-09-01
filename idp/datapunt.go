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
	IssuedAt  string `json:"iat"`
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
	baseURL  string
	rolesURL string
	secret   []byte
	client   *http.Client
}

// Constructor. Validating its config and creates the instance.
func NewDatapuntIdP(config interface{}) (*DatapuntIdP, error) {
	if dpConfig, ok := config.(map[string]interface{}); ok {
		var baseURL, secret, rolesURL string
		if baseURL, ok = dpConfig["url"].(string); !ok {
			return nil, errors.New("Missing or invalid base URL in Datapunt IdP configuration")
		}
		if secret, ok = dpConfig["secret"].(string); !ok {
			return nil, errors.New("Missing or invalid secret in Datapunt IdP configuration")
		}
		if len(secret) <= 15 {
			return nil, errors.New("Secret in Datapunt IdP configuration must be at least 15 characters long")
		}
		if rolesURL, ok = dpConfig["roles-url"].(string); !ok {
			return nil, errors.New("Missing or invalid roles URL in Datapunt IdP configuration")
		}
		return &DatapuntIdP{
			baseURL,
			rolesURL,
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
	callbackURL.Fragment = "#"

	baseURL, err = url.Parse(d.baseURL)
	if err != nil {
		return baseURL, nil, err
	}
	buQuery := baseURL.Query()
	buQuery.Set("callback", callbackURL.String())
	baseURL.RawQuery = buQuery.Encode()

	return baseURL, nil, nil
}

// User returns a User and the original opaque token.
func (d *DatapuntIdP) User(r *http.Request) (*authz.User, error) {
	q := r.URL.Query()
	if token, ok := q["aselect_credential"]; ok {
		_, err := d.jwtPayload(token[0])
		if err != nil {
			return nil, err
		}
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
