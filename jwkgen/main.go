package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
)

type JWKSet struct {
	Keys []interface{} `json:"keys"`
}

type JWK struct {
	KeyType string   `json:"kty"`
	KeyOps  []string `json:"key_ops"`
	KeyID   string   `json:"kid"`
}

type JWKEC struct {
	JWK
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
	D     string `json:"d"`
}

type JWKHMAC struct {
	JWK
	Algorithm string `json:"alg"`
	K         string `json:"k"`
}

func NewJWKEC(alg string) (*JWKEC, error) {
	var (
		c     elliptic.Curve
		l     int
		curve string
	)

	switch alg {
	case "ES256":
		curve = "P-256"
		c = elliptic.P256()
		l = 32
	case "ES384":
		curve = "P-384"
		c = elliptic.P384()
		l = 48
	case "ES512":
		curve = "P-521"
		c = elliptic.P521()
		l = 66
	default:
		return nil, fmt.Errorf("%s is not a supported algorithm", alg)
	}

	privKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}

	// make sure we have correct key sizes
	d := make([]byte, l)
	x := make([]byte, l)
	y := make([]byte, l)
	copy(d[l-len(privKey.D.Bytes()):], privKey.D.Bytes())
	copy(x[l-len(privKey.X.Bytes()):], privKey.X.Bytes())
	copy(y[l-len(privKey.Y.Bytes()):], privKey.Y.Bytes())

	// Generate a UUID as key-id
	kid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	key := &JWKEC{}
	key.KeyType = "EC"
	key.KeyID = kid.String()
	key.Curve = curve
	key.X = base64.URLEncoding.EncodeToString(x)
	key.Y = base64.URLEncoding.EncodeToString(y)
	key.D = base64.URLEncoding.EncodeToString(d)
	key.KeyOps = []string{"verify", "sign"}

	return key, nil
}

func NewJWKHMAC(alg string) (*JWKHMAC, error) {
	var keysize int
	switch alg {
	case "HS256":
		keysize = 64 // blocksize is 512 bit
	case "HS384":
		keysize = 128 // blocksize is 1024 bit
	case "HS512":
		keysize = 128 // blocksize is 1024 bit
	default:
		return nil, fmt.Errorf("%s is not a supported algorithm", alg)
	}

	// Create key
	secret := make([]byte, keysize, keysize)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err
	}

	// Generate a UUID as key-id
	kid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	key := &JWKHMAC{}
	key.KeyType = "oct"
	key.KeyID = kid.String()
	key.Algorithm = "HMAC"
	key.K = base64.URLEncoding.EncodeToString(secret)
	key.KeyOps = []string{"verify", "sign"}

	return key, nil
}

func readJWKSFromStdIn() *JWKSet {
	var jwks JWKSet
	buf := new(bytes.Buffer)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		_, err := buf.Write(scanner.Bytes())
		if err != nil {
			log.Fatalf("Error reading stdin: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("Error reading stdin: %v", err)
	}
	if err := json.Unmarshal(buf.Bytes(), &jwks); err != nil {
		log.Fatalf("Error unmarshaling jwks: %v", err)
	}
	return &jwks
}

func main() {
	// Flags
	create := flag.Bool("create", false, "Create a new JWKS instead of reading an existing one from stdin")
	alg := flag.String("alg", "", "Algorithm, one of HS256, HS384, HS512, EC256, EC384 or EC512")
	flag.Parse()

	// Grab the JWKS from stdin or create a new one
	var jwks *JWKSet
	if *create {
		jwks = &JWKSet{Keys: []interface{}{}}
	} else {
		jwks = readJWKSFromStdIn()
	}

	if len(*alg) >= 2 {
		// Create and add keys
		switch (*alg)[:2] {
		case "HS":
			key, err := NewJWKHMAC(*alg)
			if err != nil {
				log.Fatalf("Error creating key: %v", err)
			}
			jwks.Keys = append(jwks.Keys, key)
		case "ES":
			key, err := NewJWKEC(*alg)
			if err != nil {
				log.Fatalf("Error creating key: %v", err)
			}
			jwks.Keys = append(jwks.Keys, key)
		default:
			log.Fatalf("Unsupported algorithm: %s", alg)
		}
	} else if *alg != "" {
		log.Fatalf("Unsupported algorithm: %s", alg)
	}

	jwksJSON, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		log.Fatalf("Error marshaling jwks: %v", err)
	}
	fmt.Printf("%s\n", jwksJSON)
}
