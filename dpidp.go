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

// An IdP implementation of the Datapunt IdP.
type datapuntIDP struct {
	idpBaseURL   string
	oauthBaseURL string
	secret       []byte
	client       *http.Client
	dpRoles      *datapuntRoles
}

// Constructor. Validating its config and creates the instance.
func newDatapuntIDP(
	idpBaseURL string, secret []byte, oauthBaseURL string, dpRoles *datapuntRoles,
) (*datapuntIDP, error) {
	return &datapuntIDP{
		idpBaseURL, oauthBaseURL, secret, &http.Client{Timeout: 1 * time.Second}, dpRoles,
	}, nil
}

// ID returns "datapunt"
func (d *datapuntIDP) ID() string {
	return "datapunt"
}

func (d *datapuntIDP) oauth2CallbackURL() string {
	return d.oauthBaseURL + "oauth2/callback/" + d.ID()
}

// AuthnRedirect generates the Authentication redirect.
func (d *datapuntIDP) AuthnRedirect(authzRef string) (*url.URL, error) {
	var (
		baseURL *url.URL
		err     error
	)
	// Parse callback
	callbackURL, err := url.Parse(d.oauth2CallbackURL())
	if err != nil {
		return nil, err
	}
	// set ref on callback url
	cbQuery := callbackURL.Query()
	cbQuery.Set("token", authzRef)
	callbackURL.RawQuery = cbQuery.Encode()
	// Create redirect
	baseURL, err = url.Parse(d.idpBaseURL)
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
		"idp":  "Datapunt",
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
		roles, err := d.dpRoles.Get(credentialsPayload.Subject)
		if err != nil {
			return token[0], nil, err
		}
		return token[0], &oauth2.User{UID: credentialsPayload.Subject, Data: roles}, nil
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
