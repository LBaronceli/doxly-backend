package main

import (
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/LBaronceli/doxly-backend/shared/auth"
	"github.com/LBaronceli/doxly-backend/shared/httpx"
	"github.com/LBaronceli/doxly-backend/shared/telemetry"
)

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	port := envOr("PORT", "8080")

	// Prefer JWKS; fallback to env keys
	var verifier *auth.Verifier
	if jwksURL := os.Getenv("AUTH_JWKS_URL"); jwksURL != "" {
		// retry up to ~30 seconds in case auth isn't ready yet
		for i := 0; i < 20; i++ {
			pub, _, err := auth.FetchEd25519FromJWKS(jwksURL)
			if err == nil {
				verifier = auth.NewVerifier(pub)
				log.Infof("attachments-service: using JWKS verifier: %s", jwksURL)
				break
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if verifier == nil {
			log.Fatalf("jwks fetch failed after retries")
		}
	} else {
		signer, err := auth.LoadEd25519FromEnv()
		if err != nil {
			log.Fatalf("jwt keys: %v", err)
		}
		verifier = auth.NewVerifier(signer.Public())
		log.Infof("attachments-service: using env public key (fallback)")
	}


	r := chi.NewRouter()
	r.Handle("/metrics", telemetry.MetricsHandler())
	r.Get("/healthz", ok)
	r.Get("/readyz", ok)

	r.Route("/v1", func(r chi.Router) {
		r.Group(func(p chi.Router) {
			p.Use(verifier.Middleware)
			p.Post("/customers/{id}/attachments/presign", notimpl)
			p.Post("/customers/{id}/attachments/confirm", notimpl)
			p.Get("/customers/{id}/attachments", notimpl)
		})
	})

	h := httpx.Common(r)
	log.Infof("attachments-service listening on :%s", port)
	srv := &http.Server{ Addr: ":" + port, Handler: h, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second }
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { log.Fatalf("server: %v", err) }
}

func envOr(k, d string) string { if v := os.Getenv(k); v != "" { return v }; return d }
func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }
func notimpl(w http.ResponseWriter, _ *http.Request) { http.Error(w, "not implemented yet", http.StatusNotImplemented) }
