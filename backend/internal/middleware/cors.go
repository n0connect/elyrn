package middleware

import (
	"net/http"
	"strings"
	"sync"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
	"elyrn/internal/utils"
)

const (
	headerOrigin = "Origin"
	// corsPreflightMaxAge is how long, in seconds, a browser may cache a preflight answer
	corsPreflightMaxAge = "3600"
)

var (
	allowedOrigins map[string]struct{}
	corsLogger     = utils.NewLogger("CORS")
	corsOnce       sync.Once
)

func loadAllowedOrigins() {
	corsOnce.Do(func() {
		allowedOrigins = make(map[string]struct{})

		raw := config.GetAllowedOrigins()
		if raw == "" {
			corsLogger.Warn("CORS: ALLOWED_ORIGINS not set; no origins will be allowed")
			return
		}
		if raw == "*" {
			corsLogger.Warn("CORS: wildcard origins are not allowed; no origins will be allowed")
			return
		}

		for _, o := range strings.Split(raw, ",") {
			o = strings.TrimSpace(o)
			if o == "" {
				continue
			}
			allowedOrigins[o] = struct{}{}
		}
		corsLogger.Info("CORS: whitelist enabled from ALLOWED_ORIGINS, count=%d", len(allowedOrigins))
	})
}

// isOriginAllowed is an exact whitelist match: scheme, host and port must all be listed in
// ALLOWED_ORIGINS. No prefix or pattern matching ("http://localhost:3000.evil.example").
func isOriginAllowed(origin string) bool {
	loadAllowedOrigins()
	_, ok := allowedOrigins[origin]
	return ok
}

func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		loadAllowedOrigins()
		origin := r.Header.Get(headerOrigin)

		if origin != "" {
			if isOriginAllowed(origin) {
				// Echo origin
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", headerOrigin)

				// Whitelist: exactly the methods and headers the API uses
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", utils.HeaderContentType)
				w.Header().Set("Access-Control-Max-Age", corsPreflightMaxAge)
			} else {
				// If Preflight then return error
				// SECURITY: Generic error message to prevent information leakage
				if r.Method == http.MethodOptions {
					apperr.Write(w, "CORSMiddleware: preflight", apperr.CrossOrigin)
					return
				}
				// Don't send headers for any other requests.
			}
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent) // 204
			return
		}

		next(w, r)
	}
}
