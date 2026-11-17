package middleware

import (
	"net/http"

	"elyrn/internal/utils"
)

// apiCSP makes every API response inert: JSON is data, never a document that loads or runs anything
const apiCSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

// The cross-origin headers, fixed: the app loads nothing from other origins. nginx sends the
// same three on every response the browser sees (nginx-site.conf) and hides these copies of
// them on /api/ (nginx-api-proxy.conf), so a browser never gets two of one; they are set here
// for a backend reached without nginx. Not configurable: a setting here could only disagree
// with nginx (the SEC_HEADER_* settings of earlier releases are gone and ignored).
const (
	crossOriginOpenerPolicy   = "same-origin"
	crossOriginResourcePolicy = "same-origin"
	crossOriginEmbedderPolicy = "require-corp"
)

// permissionsPolicy denies every powerful browser feature the app never uses
const permissionsPolicy = "accelerometer=(), autoplay=(), browsing-topics=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), hid=(), interest-cohort=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()"

// SecurityHeadersMiddleware adds the API security headers (nginx sets the page CSP)
func SecurityHeadersMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", apiCSP)
		w.Header().Set(utils.HeaderCacheControl, utils.CacheNoStore)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", permissionsPolicy)

		// No HSTS here: nginx is its one source, on every HTTPS answer of the clearnet listener,
		// the page included (nginx-hsts.sh, nginx-site.conf)

		w.Header().Set("Cross-Origin-Opener-Policy", crossOriginOpenerPolicy)
		w.Header().Set("Cross-Origin-Resource-Policy", crossOriginResourcePolicy)
		w.Header().Set("Cross-Origin-Embedder-Policy", crossOriginEmbedderPolicy)

		next(w, r)
	}
}
