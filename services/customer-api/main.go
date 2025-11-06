package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	// Postgres error types (pgx or lib/pq)
	"github.com/jackc/pgconn"
	"github.com/lib/pq"

	"github.com/LBaronceli/doxly-backend/shared/auth"
	"github.com/LBaronceli/doxly-backend/shared/db"
	"github.com/LBaronceli/doxly-backend/shared/httpx"
	"github.com/LBaronceli/doxly-backend/shared/telemetry"
)

/*************** Build info (set via -ldflags) ***************/
var (
	version = "dev"
	builtAt = "unknown"
)

/*************** Server ***************/

type Server struct {
	log   *zap.SugaredLogger
	store *Store
	pub   ed25519.PublicKey
}

func envOr(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }

func httpJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, publicMsg string, err error, extraFields ...any) {
	reqID := middleware.GetReqID(r.Context())
	fields := append([]any{"rid", reqID}, extraFields...)
	if err != nil {
		s.log.With(fields...).Errorf("%s: %v", publicMsg, err)
	} else {
		s.log.With(fields...).Errorf("%s", publicMsg)
	}
	httpJSON(w, status, map[string]string{"error": publicMsg})
}

/*************** main ***************/

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	port := envOr("PORT", "8080")
	ctx := context.Background()

	sqlxDB := db.MustOpen(ctx, "DATABASE_URL")
	defer sqlxDB.Close()

	// Resolve JWT verification key (prefer JWKS)
	var pub ed25519.PublicKey
	if jwksURL := os.Getenv("AUTH_JWKS_URL"); jwksURL != "" {
		for i := 0; i < 20; i++ {
			p, _, err := auth.FetchEd25519FromJWKS(jwksURL)
			if err == nil {
				pub = p
				log.Infof("customer-api v%s (%s) using JWKS: %s", version, builtAt, jwksURL)
				break
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if pub == nil {
			log.Fatalf("jwks fetch failed after retries")
		}
	} else {
		signer, err := auth.LoadEd25519FromEnv()
		if err != nil {
			log.Fatalf("jwt keys: %v", err)
		}
		pub = signer.Public()
		log.Infof("customer-api v%s (%s) using env public key", version, builtAt)
	}

	s := &Server{
		log:   log,
		store: &Store{db: sqlxDB},
		pub:   pub,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP)
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		cx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if err := sqlxDB.DB.PingContext(cx); err != nil {
			http.Error(w, "db not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(pr chi.Router) {
			pr.Use(s.jwtVerifierMiddleware())
			pr.Post("/customers", s.createCustomer)
			pr.Get("/customers", s.listCustomers)
			pr.Get("/customers/{id}", s.getCustomer)
			pr.Put("/customers/{id}", s.updateCustomer)
			pr.Delete("/customers/{id}", s.deleteCustomer)
		})
	})

	h := httpx.Common(r)
	log.Infof("customer-api listening on :%s", port)
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

/*************** Store ***************/

type Store struct{ db *sqlx.DB }

type Customer struct {
	ID        string    `db:"id" json:"id"`
	OrgID     string    `db:"org_id" json:"org_id"`
	Name      string    `db:"name" json:"name"`
	Email     *string   `db:"email" json:"email,omitempty"`
	Phone     *string   `db:"phone" json:"phone,omitempty"`
	Notes     *string   `db:"notes" json:"notes,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	UpdatedAt time.Time `db:"updated_at" json:"updated_at"`
}

var ErrEmailExists = errors.New("email already exists")

// fast-path existence check (citext means = is case-insensitive)
// avoids hitting 23505 in the hot path and lets us return 409 deterministically
func (s *Store) emailExists(ctx context.Context, orgID string, email *string) (bool, error) {
	if email == nil || strings.TrimSpace(*email) == "" {
		return false, nil
	}
	var exists bool
	err := s.db.QueryRowxContext(ctx,
		`select true from customers where org_id=$1 and email=$2 limit 1`,
		orgID, strings.TrimSpace(*email),
	).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return exists, err
}

// Create: pre-check -> 409; still keep ON CONFLICT DO NOTHING RETURNING as a guard.
func (s *Store) CreateCustomer(ctx context.Context, orgID, name string, email, phone, notes *string) (Customer, error) {
	if ok, err := s.emailExists(ctx, orgID, email); err != nil {
		return Customer{}, err
	} else if ok {
		return Customer{}, ErrEmailExists
	}

	var c Customer
	q := `
		insert into customers (org_id, name, email, phone, notes)
		values ($1,$2,$3,$4,$5)
		on conflict do nothing
		returning id, org_id, name, email, phone, notes, created_at, updated_at
	`
	err := s.db.QueryRowxContext(ctx, q, orgID, name, email, phone, notes).StructScan(&c)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || isUniqueViolation(err) || looksLikeUniqueString(err) {
			return c, ErrEmailExists
		}
		return c, err
	}
	return c, nil
}

func (s *Store) GetCustomer(ctx context.Context, orgID, id string) (Customer, error) {
	var c Customer
	err := s.db.GetContext(ctx, &c, `
		select id, org_id, name, email, phone, notes, created_at, updated_at
		from customers where id=$1 and org_id=$2
	`, id, orgID)
	return c, err
}

// Update: if email changes to an existing one, map to 409
func (s *Store) UpdateCustomer(ctx context.Context, orgID, id, name string, email, phone, notes *string) (Customer, error) {
	// pre-check only when email provided
	if email != nil && strings.TrimSpace(*email) != "" {
		var exists bool
		// ensure we don't flag the same row: exclude current id
		err := s.db.QueryRowxContext(ctx,
			`select true from customers where org_id=$1 and email=$2 and id<>$3 limit 1`,
			orgID, strings.TrimSpace(*email), id,
		).Scan(&exists)
		if err == sql.ErrNoRows {
			exists = false
		} else if err != nil {
			return Customer{}, err
		}
		if exists {
			return Customer{}, ErrEmailExists
		}
	}

	var c Customer
	q := `
		update customers
		set name=$3, email=$4, phone=$5, notes=$6
		where id=$1 and org_id=$2
		returning id, org_id, name, email, phone, notes, created_at, updated_at
	`
	err := s.db.QueryRowxContext(ctx, q, id, orgID, name, email, phone, notes).StructScan(&c)
	if err != nil {
		if isUniqueViolation(err) || looksLikeUniqueString(err) {
			return c, ErrEmailExists
		}
		return c, err
	}
	return c, nil
}

func (s *Store) DeleteCustomer(ctx context.Context, orgID, id string) error {
	res, err := s.db.ExecContext(ctx, `delete from customers where id=$1 and org_id=$2`, id, orgID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListCustomers(ctx context.Context, orgID string, limit, offset int, q string) ([]Customer, error) {
	items := []Customer{}
	if q != "" {
		q = "%" + strings.ToLower(q) + "%"
		err := s.db.SelectContext(ctx, &items, `
			select id, org_id, name, email, phone, notes, created_at, updated_at
			from customers
			where org_id=$1 and (lower(name) like $2 or lower(coalesce(email,'')) like $2)
			order by created_at desc
			limit $3 offset $4
		`, orgID, q, limit, offset)
		return items, err
	}
	err := s.db.SelectContext(ctx, &items, `
		select id, org_id, name, email, phone, notes, created_at, updated_at
		from customers
		where org_id=$1
		order by created_at desc
		limit $2 offset $3
	`, orgID, limit, offset)
	return items, err
}

/*************** Postgres error helpers ***************/

func pgCode(err error) string {
	var perr *pgconn.PgError
	if errors.As(err, &perr) {
		return perr.Code
	}
	var pqe *pq.Error
	if errors.As(err, &pqe) {
		return string(pqe.Code)
	}
	return ""
}

func isUniqueViolation(err error) bool { return pgCode(err) == "23505" }

func looksLikeUniqueString(err error) bool {
	if err == nil { return false }
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sqlstate 23505") ||
		strings.Contains(msg, "duplicate key value violates unique constraint")
}

/*************** Auth helpers ***************/

type ctxClaimsKey struct{}

func (s *Server) jwtVerifierMiddleware() func(http.Handler) http.Handler {
	public := s.pub
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

func getClaims(r *http.Request) jwt.MapClaims {
	if v := r.Context().Value(ctxClaimsKey{}); v != nil {
		if c, ok := v.(jwt.MapClaims); ok { return c }
	}
	return jwt.MapClaims{}
}

func orgFromJWT(r *http.Request) (string, bool) {
	claims := getClaims(r)
	orgID, _ := claims["org_id"].(string)
	return orgID, orgID != ""
}

/*************** Handlers ***************/

type createReq struct {
	Name  string  `json:"name"`
	Email *string `json:"email"`
	Phone *string `json:"phone"`
	Notes *string `json:"notes"`
}

func (s *Server) createCustomer(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r); if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	var in createReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Name) == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json/name"}); return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); defer cancel()
	c, err := s.store.CreateCustomer(ctx, orgID, strings.TrimSpace(in.Name), in.Email, in.Phone, in.Notes)
	if err != nil {
		if errors.Is(err, ErrEmailExists) || isUniqueViolation(err) || looksLikeUniqueString(err) {
			s.fail(w, r, http.StatusConflict, "email already exists", err, "org_id", orgID, "email", safePtr(in.Email)); return
		}
		s.fail(w, r, http.StatusInternalServerError, "create failed", err, "org_id", orgID, "name", in.Name); return
	}
	httpJSON(w, http.StatusCreated, c)
}

func (s *Server) getCustomer(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r); if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	id := chi.URLParam(r, "id")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); defer cancel()
	c, err := s.store.GetCustomer(ctx, orgID, id)
	if err != nil {
		if err == sql.ErrNoRows { httpJSON(w, http.StatusNotFound, map[string]string{"error": "not found"}); return }
		httpJSON(w, http.StatusInternalServerError, map[string]string{"error": "get failed"}); return
	}
	httpJSON(w, http.StatusOK, c)
}

func (s *Server) updateCustomer(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r); if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	id := chi.URLParam(r, "id")
	var in createReq
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Name) == "" {
		httpJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json/name"}); return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); defer cancel()
	c, err := s.store.UpdateCustomer(ctx, orgID, id, strings.TrimSpace(in.Name), in.Email, in.Phone, in.Notes)
	if err != nil {
		if err == sql.ErrNoRows { s.fail(w, r, http.StatusNotFound, "not found", err, "org_id", orgID, "id", id); return }
		if errors.Is(err, ErrEmailExists) || isUniqueViolation(err) || looksLikeUniqueString(err) {
			s.fail(w, r, http.StatusConflict, "email already exists", err, "org_id", orgID, "id", id, "email", safePtr(in.Email)); return
		}
		s.fail(w, r, http.StatusInternalServerError, "update failed", err, "org_id", orgID, "id", id); return
	}
	httpJSON(w, http.StatusOK, c)
}

func (s *Server) deleteCustomer(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r); if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	id := chi.URLParam(r, "id")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); defer cancel()
	if err := s.store.DeleteCustomer(ctx, orgID, id); err != nil {
		if err == sql.ErrNoRows { s.fail(w, r, http.StatusNotFound, "not found", err, "org_id", orgID, "id", id); return }
		s.fail(w, r, http.StatusInternalServerError, "delete failed", err, "org_id", orgID, "id", id); return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listCustomers(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromJWT(r); if !ok { http.Error(w, "unauthorized", http.StatusUnauthorized); return }
	limit, offset := 50, 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 { limit = n }
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 { offset = n }
	}
	q := r.URL.Query().Get("q")

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second); defer cancel()
	items, err := s.store.ListCustomers(ctx, orgID, limit, offset, q)
	if err != nil {
		s.fail(w, r, http.StatusInternalServerError, "list failed", err, "org_id", orgID, "limit", limit, "offset", offset, "q", q); return
	}
	httpJSON(w, http.StatusOK, map[string]any{"items": items, "limit": limit, "offset": offset})
}

/*************** small util ***************/

func safePtr(s *string) string { if s == nil { return "" }; return *s }
