package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/LBaronceli/doxly-backend/shared/auth"
	"github.com/LBaronceli/doxly-backend/shared/db"
	"github.com/LBaronceli/doxly-backend/shared/httpx"
	"github.com/LBaronceli/doxly-backend/shared/telemetry"
)

type Server struct {
	log    *zap.SugaredLogger
	signer *auth.Signer
	db     *sqlx.DB
}

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	port := envOr("PORT", "8080")

	// Open DB (retry logic is inside MustOpen)
	sqlxDB := db.MustOpen(context.Background(), "DATABASE_URL")
	defer sqlxDB.Close()

	// Auth is the issuer: load Ed25519 signer from env
	signer, err := auth.LoadEd25519FromEnv()
	if err != nil {
		log.Fatalf("jwt keys: %v", err)
	}

	s := &Server{log: log, signer: signer, db: sqlxDB}

	r := chi.NewRouter()
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := s.db.DB.PingContext(ctx); err != nil {
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	// Public JWKS so other services can verify tokens
	r.Get("/.well-known/jwks.json", auth.JwksHandler(signer.Public(), signer.KID()))

	// Auth API
	r.Route("/v1", func(r chi.Router) {
		r.Post("/signup", s.handleSignup)
		r.Post("/login", s.handleLogin)

		// Protected subrouter: requires Bearer token
		r.Group(func(pr chi.Router) {
			pr.Use(s.jwtVerifierMiddleware())
			pr.Get("/me", s.handleMe)
		})
	})

	// Common middlewares (logger, recoverer, requestID, etc.)
	h := httpx.Common(r)

	log.Infof("auth-service listening on :%s", port)
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      h,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
}

func envOr(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }

/* ===================== /v1/signup ===================== */

type signupReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	OrgName  string `json:"org_name"`
}
type signupResp struct {
	Token string `json:"token"`
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var in signupReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	in.Email = strings.TrimSpace(strings.ToLower(in.Email))
	in.OrgName = strings.TrimSpace(in.OrgName)
	if !strings.Contains(in.Email, "@") || len(in.Password) < 8 || in.OrgName == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid email/password/org_name"})
		return
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash error"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	tx, err := s.db.BeginTxx(ctx, &sql.TxOptions{})
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx begin error"})
		return
	}
	defer func() { _ = tx.Rollback() }()

	var orgID, userID string
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id`, in.OrgName,
	).Scan(&orgID); err != nil {
		s.log.Errorf("create org error: %v", err)
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "create org"})
		return
	}

	if err := tx.QueryRowContext(ctx,
		`INSERT INTO users (org_id,email,password_hash,role)
		 VALUES ($1,$2,$3,'admin') RETURNING id`,
		orgID, in.Email, string(pwHash),
	).Scan(&userID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate key") {
			httpJSON(w, http.StatusConflict, map[string]string{"error": "email exists"})
			return
		}
		s.log.Errorf("create user error: %v", err)
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "create user"})
		return
	}

	if err := tx.Commit(); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "tx commit"})
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    userID,
		"org_id": orgID,
		"role":   "admin",
		"iat":    now.Unix(),
		"exp":    now.Add(24 * time.Hour).Unix(),
		"iss":    "doxly-auth",
		"aud":    "doxly",
	}
	tok, err := s.signer.Sign(claims)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign token"})
		return
	}
	httpJSON(w, http.StatusCreated, signupResp{Token: tok})
}

/* ===================== /v1/login ===================== */

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type loginResp struct {
	Token string `json:"token"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in loginReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || in.Password == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "missing email/password"})
		return
	}

	// Look up user by email
	var userID, orgID, role, pwHash string
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	err := s.db.QueryRowContext(ctx,
		`select id, org_id, role, password_hash from users where lower(email) = $1`,
		email,
	).Scan(&userID, &orgID, &role, &pwHash)
	if err != nil {
		if err == sql.ErrNoRows {
			httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		s.log.Errorf("login query error: %v", err)
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(pwHash), []byte(in.Password)) != nil {
		httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    userID,
		"org_id": orgID,
		"role":   role,
		"iat":    now.Unix(),
		"exp":    now.Add(24 * time.Hour).Unix(),
		"iss":    "doxly-auth",
		"aud":    "doxly",
	}
	tok, err := s.signer.Sign(claims)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign token"})
		return
	}
	httpJSON(w, http.StatusOK, loginResp{Token: tok})
}

/* ===================== /v1/me (protected) ===================== */

type meResp struct {
	UserID string `json:"user_id"`
	OrgID  string `json:"org_id"`
	Role   string `json:"role"`
	Email  string `json:"email"`
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	userID, _ := claims["sub"].(string)
	orgID, _ := claims["org_id"].(string)

	// Fetch fresh data (so we return current email/role)
	var email, role string
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	err := s.db.QueryRowContext(ctx,
		`select email, role from users where id = $1 and org_id = $2`,
		userID, orgID,
	).Scan(&email, &role)
	if err != nil {
		if err == sql.ErrNoRows {
			httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "user not found"})
			return
		}
		s.log.Errorf("me query error: %v", err)
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "server error"})
		return
	}

	httpJSON(w, http.StatusOK, meResp{
		UserID: userID,
		OrgID:  orgID,
		Role:   role,
		Email:  email,
	})
}

/* ===================== middleware & helpers ===================== */

func (s *Server) jwtVerifierMiddleware() func(http.Handler) http.Handler {
	public := s.signer.Public()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ah := r.Header.Get("Authorization")
			if !strings.HasPrefix(strings.ToLower(ah), "bearer ") {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
				return
			}
			tokenStr := strings.TrimSpace(ah[len("Bearer "):])

			claims := jwt.MapClaims{}
			tok, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (any, error) {
				if token.Method.Alg() != jwt.SigningMethodEdDSA.Alg() {
					return nil, jwt.ErrTokenUnverifiable
				}
				return public, nil
			})
			if err != nil || !tok.Valid {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
				return
			}

			// Light audience/issuer checks
			if aud, _ := claims["aud"].(string); aud != "doxly" {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad audience"})
				return
			}
			if iss, _ := claims["iss"].(string); iss != "doxly-auth" {
				httpJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad issuer"})
				return
			}

			ctx := context.WithValue(r.Context(), ctxClaimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type ctxClaimsKey struct{}

func getClaims(r *http.Request) jwt.MapClaims {
	if v := r.Context().Value(ctxClaimsKey{}); v != nil {
		if c, ok := v.(jwt.MapClaims); ok {
			return c
		}
	}
	return jwt.MapClaims{}
}

func httpJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
