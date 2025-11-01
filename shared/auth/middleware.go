package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type ContextKey string

const (
	CtxUserID ContextKey = "user_id"
	CtxOrgID  ContextKey = "org_id"
	CtxRole   ContextKey = "role"
)

type Verifier struct {
	pub ed25519.PublicKey
}

func NewVerifier(pub ed25519.PublicKey) *Verifier { return &Verifier{pub: pub} }

func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		if !strings.HasPrefix(authz, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized); return
		}
		tokenStr := strings.TrimPrefix(authz, "Bearer ")

		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			if t.Method != jwt.SigningMethodEdDSA { return nil, errors.New("wrong alg") }
			return v.pub, nil
		})
		if err != nil { http.Error(w, "invalid token", http.StatusUnauthorized); return }

		// basic expiry check
		if exp, ok := claims["exp"].(float64); ok && time.Now().Unix() > int64(exp) {
			http.Error(w, "token expired", http.StatusUnauthorized); return
		}

		ctx := context.WithValue(r.Context(), CtxUserID, claims["sub"])
		ctx = context.WithValue(ctx, CtxOrgID, claims["org_id"])
		ctx = context.WithValue(ctx, CtxRole, claims["role"])
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
