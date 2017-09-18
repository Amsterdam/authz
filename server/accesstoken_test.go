package server

import (
	"reflect"
	"testing"
)

func TestEncode(t *testing.T) {
	var (
		subject = "subject"
		scopes  = []string{"scope1", "scope2"}
	)
	enc := accessTokenEnc()
	jwt, err := enc.Encode(subject, scopes)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := enc.decodeJWT(jwt)
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
	enc := accessTokenEnc()
	for i := 0; i < b.N; i++ {
		enc.Encode("subject", []string{"abc", "def"})
	}
}
