package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
)

type jwkKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type jwks struct {
	Keys []jwkKey `json:"keys"`
}

func b64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func JwksHandler(pub ed25519.PublicKey, kid string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := jwkKey{
			Kty: "OKP", Crv: "Ed25519", X: b64URL(pub), Use: "sig", Alg: "EdDSA", Kid: kid,
		}
		js, _ := json.Marshal(jwks{Keys: []jwkKey{key}})
		w.Header().Set("Content-Type", "application/json")
		w.Write(js)
	}
}
