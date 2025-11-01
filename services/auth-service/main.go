package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/LBaronceli/doxly-backend/shared/auth"
	"github.com/LBaronceli/doxly-backend/shared/db"
	"github.com/LBaronceli/doxly-backend/shared/httpx"
	"github.com/LBaronceli/doxly-backend/shared/telemetry"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	port := envOr("PORT", "8080")

	ctx := context.Background()
	_ = db.MustOpen(ctx, "DATABASE_URL") // keep connection warm for readiness later

	signer, err := auth.LoadEd25519FromEnv()
	if err != nil { log.Fatalf("jwt keys: %v", err) }

	r := chi.NewRouter()
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })

	// JWKS for other services to verify tokens
	r.Get("/.well-known/jwks.json", auth.JwksHandler(signer.Public(), signer.KID()))

	// v1 auth endpoints (stubs for now)
	r.Route("/v1", func(r chi.Router) {
		r.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not implemented yet", http.StatusNotImplemented)
		})
		r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not implemented yet", http.StatusNotImplemented)
		})
		r.Get("/me", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "not implemented yet", http.StatusNotImplemented)
		})
	})

	// common middlewares
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

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" { return v }
	return d
}

func writeJSON(w http.ResponseWriter, v any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

var _ = prometheus.NewRegistry // keeps prometheus dep referenced
