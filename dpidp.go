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

	"github.com/amsterdam/authz/oauth2"
	log "github.com/sirupsen/logrus"
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
type datapuntIDP struct {
	baseURL     string
	accountsURL *url.URL
	secret      []byte
	apiKey      string
	client      *http.Client
}

// Constructor. Validating its config and creates the instance.
func newDatapuntIDP(
	baseURL string, accountsURL string, secret []byte, apiKey string,
) (*datapuntIDP, error) {
	accURL, err := url.Parse(accountsURL)
	if err != nil {
		return nil, errors.New("Invalid accounts URL for Datapunt IdP")
	}
	return &datapuntIDP{
		baseURL, accURL, secret, apiKey, &http.Client{Timeout: 1 * time.Second},
	}, nil
}

// ID returns "datapunt"
func (d *datapuntIDP) ID() string {
	return "datapunt"
}

// AuthnRedirect generates the Authentication redirect.
func (d *datapuntIDP) AuthnRedirect(callbackURL *url.URL, authzRef string) (*url.URL, error) {
	var (
		baseURL *url.URL
		err     error
	)
	// set ref on callback url
	cbQuery := callbackURL.Query()
	cbQuery.Set("token", authzRef)
	callbackURL.RawQuery = cbQuery.Encode()
	// Create redirect
	baseURL, err = url.Parse(d.baseURL)
	if err != nil {
		return nil, err
	}
	buQuery := baseURL.Query()
	buQuery.Set("callback", callbackURL.String())
	baseURL.RawQuery = buQuery.Encode()
	// return redirect
	return baseURL, nil
}

// User returns a User and the original opaque token.
func (d *datapuntIDP) AuthnCallback(r *http.Request) (string, *oauth2.User, error) {
	// Create context logger
	logFields := log.Fields{
		"type": "authn callback request",
		"uri":  r.RequestURI,
	}
	logger := log.WithFields(logFields)
	// Handle request
	q := r.URL.Query()
	token, ok := q["token"]
	if !ok {
		logger.Infoln("Token parameter missing from request")
		return "", nil, nil
	}
	if credentials, ok := q["credentials"]; ok {
		credentialsPayload, err := d.jwtPayload(credentials[0])
		if err != nil {
			logger.WithFields(log.Fields{
				"token": credentials[0],
				"error": err,
			}).Warn("Couldn't decode datapunt IdP token / jwt")
			return token[0], nil, nil
		}
		user, err := d.user(credentialsPayload.Subject)
		return token[0], user, err
	}
	logger.Infoln("Credentials parameter missing from request")
	return token[0], nil, nil
}

func (d *datapuntIDP) jwtPayload(token string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		var (
			header  jwtHeader
			payload jwtPayload
		)
		b64header, b64payload, b64digest := parts[0], parts[1], parts[2]
		// Decode and verify the header
		if jsonHeader, err := base64.RawURLEncoding.DecodeString(b64header); err == nil {
			if err = json.Unmarshal(jsonHeader, &header); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
		if header.Algorithm != "HS256" {
			return nil, fmt.Errorf("Invalid credentials: unsupported algorithm %s", header.Algorithm)
		}
		if header.Type != "JWT" {
			return nil, fmt.Errorf("Invalid credentials: unsupported token type %s", header.Type)
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
			if err = json.Unmarshal(jsonPayload, &payload); err != nil {
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

func (d *datapuntIDP) user(uid string) (*oauth2.User, error) {
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
	return &oauth2.User{UID: uid, Data: roles}, nil
}
