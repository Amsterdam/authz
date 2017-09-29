package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestEncode(t *testing.T) {
	var (
		subject = "subject"
		scopes  = []string{"scope1", "scope2"}
	)
	enc := newAccessTokenEncoder([]byte("test"), 10, "test")
	jwt, err := enc.Encode(subject, scopes)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := decodeJWT(jwt, "test")
	if err != nil {
		t.Fatal(err)
	}
	if payload.Subject != subject {
		t.Fatalf("JWT subject doesn't match (expected: %s, got %s)", subject, payload.Subject)
	}
	if !reflect.DeepEqual(scopes, payload.Scopes) {
		t.Fatalf("Scopes dont match (expected: %s, got %s)", scopes, payload.Scopes)
	}
	if jwt2, err := enc.jwt(header, payload); err != nil {
		t.Fatal(err)
	} else if jwt2 != jwt {
		t.Fatalf("Re-computed JWT doesnt match original (original: %s, computed: %s)", jwt, jwt2)
	}
}

func BenchmarkEncode(b *testing.B) {
	enc := newAccessTokenEncoder([]byte("test"), 10, "test")
	for i := 0; i < b.N; i++ {
		if _, err := enc.Encode("subject", []string{"abc", "def"}); err != nil {
			b.Fatal(err)
		}
	}
}

func decodeJWT(jwt string, secret string) (*accessTokenJWTHeader, *accessTokenJWTPayload, error) {
	var (
		header  accessTokenJWTHeader
		payload accessTokenJWTPayload
	)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("JWT shoud have 3 parts, has %d: ", len(parts))
	}
	b64header, b64payload, b64digest := parts[0], parts[1], parts[2]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(fmt.Sprintf("%s.%s", b64header, b64payload)))
	computedB64digest := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if b64digest != computedB64digest {
		return nil, nil, fmt.Errorf(
			"Can't verify accesstoken signature (got: %s, computed: %s)",
			b64digest, computedB64digest,
		)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(b64header)
	if err != nil {
		return nil, nil, err
	}
	if err = json.Unmarshal(rawHeader, &header); err != nil {
		return nil, nil, err
	}
	rawPayload, err := base64.RawURLEncoding.DecodeString(b64payload)
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		return nil, nil, err
	}
	return &header, &payload, nil
}
