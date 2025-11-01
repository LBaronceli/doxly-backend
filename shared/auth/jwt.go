package auth

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

func LoadEd25519FromEnv() (*Signer, error) {
	privB64 := os.Getenv("JWT_PRIVATE_KEY_BASE64")
	pubB64 := os.Getenv("JWT_PUBLIC_KEY_BASE64")
	kid := os.Getenv("JWT_KID")
	if kid == "" { kid = "doxly-key-1" }
	if privB64 == "" || pubB64 == "" {
		return nil, errors.New("missing JWT_PRIVATE_KEY_BASE64 or JWT_PUBLIC_KEY_BASE64")
	}
	privDER, _ := base64.StdEncoding.DecodeString(privB64)
	pubDER, _ := base64.StdEncoding.DecodeString(pubB64)

	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	// Accept raw DER or PEM
	if p, _ := pem.Decode(privDER); p != nil {
		key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		if err != nil { return nil, err }
		privKey = key.(ed25519.PrivateKey)
	} else {
		key, err := x509.ParsePKCS8PrivateKey(privDER)
		if err != nil { return nil, err }
		privKey = key.(ed25519.PrivateKey)
	}

	if p, _ := pem.Decode(pubDER); p != nil {
		key, err := x509.ParsePKIXPublicKey(p.Bytes)
		if err != nil { return nil, err }
		pubKey = key.(ed25519.PublicKey)
	} else {
		key, err := x509.ParsePKIXPublicKey(pubDER)
		if err != nil { return nil, err }
		pubKey = key.(ed25519.PublicKey)
	}

	return &Signer{priv: privKey, pub: pubKey, kid: kid}, nil
}

func (s *Signer) Sign(claims jwt.MapClaims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	t.Header["kid"] = s.kid
	return t.SignedString(s.priv)
}

func (s *Signer) Public() ed25519.PublicKey { return s.pub }
func (s *Signer) KID() string               { return s.kid }
