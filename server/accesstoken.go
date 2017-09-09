package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type accessTokenJWTHeader struct {
	Type      string `json:"typ"`
	Algorithm string `json:"alg"`
}

type accessTokenJWTPayload struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	JWTId     string   `json:"jti"`
	Scopes    []string `json:"scopes"`
	// Temporary for backwards compatibility: level
	Authz int `json:"authz"`
}

type accessTokenEncoder struct {
	Secret   []byte
	Lifetime int64
	Issuer   string
}

func newAccessTokenEncoder(secret []byte, lifetime int64, issuer string) *accessTokenEncoder {
	return &accessTokenEncoder{secret, lifetime, issuer}
}

func (enc *accessTokenEncoder) Encode(subject string, scopes []string) (string, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	// Temporary for backwards compatibility
	level := 1
	if subject != "Medewerker" {
		level = 3
	}
	now := time.Now().Unix()
	header := &accessTokenJWTHeader{
		Type:      "JWT",
		Algorithm: "HS256",
	}
	payload := &accessTokenJWTPayload{
		Issuer:    enc.Issuer,
		Subject:   subject,
		IssuedAt:  now,
		NotBefore: now - 10,
		ExpiresAt: now + enc.Lifetime,
		JWTId:     jti.String(),
		Scopes:    scopes,
		Authz:     level,
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadJson, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJson)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJson)
	mac := hmac.New(sha256.New, enc.Secret)
	mac.Write([]byte(fmt.Sprintf("%s.%s", headerB64, payloadB64)))
	digest := mac.Sum(nil)
	digestB64 := base64.RawURLEncoding.EncodeToString(digest)
	return fmt.Sprintf("%s.%s.%s", headerB64, payloadB64, digestB64), nil
}
