package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// use different wrapper type to avoid redeclaration; reuse jwkKey from jwk.go
type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

// FetchEd25519FromJWKS fetches a JWKS and returns the first Ed25519 public key.
func FetchEd25519FromJWKS(url string) (ed25519.PublicKey, string, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.New("jwks http status: " + resp.Status)
	}

	var set jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, "", err
	}
	for _, k := range set.Keys {
		if k.Kty == "OKP" && k.Crv == "Ed25519" && k.Alg == "EdDSA" && k.X != "" {
			x, err := base64.RawURLEncoding.DecodeString(k.X)
			if err != nil {
				continue
			}
			return ed25519.PublicKey(x), k.Kid, nil
		}
	}
	return nil, "", errors.New("no ed25519 key in jwks")
}
