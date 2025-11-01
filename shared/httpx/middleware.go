package httpx

import (
	"net/http"

	"github.com/go-chi/chi/v5/middleware"
)

func Common(h http.Handler) http.Handler {
	chain := middleware.Chain(
		middleware.RequestID,
		middleware.RealIP,
		middleware.Recoverer,
		middleware.Logger,
	)
	return chain.Handler(h)
}
