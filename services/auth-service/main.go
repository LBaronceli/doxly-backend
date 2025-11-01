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

	// Open DB (with retry inside MustOpen)
	sqlxDB := db.MustOpen(context.Background(), "DATABASE_URL")
	defer sqlxDB.Close()

	// Load JWT signer (auth is the issuer)
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
		r.Post("/login", s.handleLogin) // to be implemented
		r.Get("/me", s.handleMe)        // to be implemented
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

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	httpJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	httpJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func httpJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
