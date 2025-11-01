package httpx

import (
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Common wraps an http.Handler with standard middlewares.
// We compose them manually instead of using middleware.Chain for max compatibility.
func Common(h http.Handler) http.Handler {
	// Order matters: assign request ID, get real IP, recover panics, then log
	return chimw.RequestID(
		chimw.RealIP(
			chimw.Recoverer(
				chimw.Logger(h),
			),
		),
	)
}
