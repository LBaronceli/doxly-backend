package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
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
	dbc := db.MustOpen(ctx, "DATABASE_URL")
	_ = dbc

	// fetch JWKS directly later; for now, we read public key from env to keep simple
	signer, err := auth.LoadEd25519FromEnv()
	if err != nil { log.Fatalf("jwt keys: %v", err) }
	verifier := auth.NewVerifier(signer.Public())

	r := chi.NewRouter()
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", ok)
	r.Get("/readyz", ok)

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(protected chi.Router) {
			protected.Use(verifier.Middleware)
			protected.Post("/customers", notimpl)
			protected.Get("/customers", notimpl)
			protected.Get("/customers/{id}", notimpl)
			protected.Put("/customers/{id}", notimpl)
			protected.Delete("/customers/{id}", notimpl)
			protected.Post("/customers/{id}/notes", notimpl)
		})
	})

	h := httpx.Common(r)
	log.Infof("customer-api listening on :%s", port)
	srv := &http.Server{ Addr: ":" + port, Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second }
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Fatalf("server: %v", err) }
}

func envOr(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }
func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }
func notimpl(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not implemented yet", http.StatusNotImplemented) }
