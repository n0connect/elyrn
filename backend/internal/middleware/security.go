package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"elyrn/internal/config"
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

		// HSTS: nginx never sends it, so this is its only source (on API answers, which a browser
		// applies to the whole host). HTTPS is known from nginx's X-Forwarded-Proto, which carries
		// the outer proxy's word only from EDGE_TRUSTED_PROXIES (nginx.conf).
		if config.IsProductionMode() && IsRequestHTTPS(r) {
			maxAge := config.GetHSTSMaxAge()
			if maxAge > 0 {
				hsts := []string{"max-age=" + strconv.Itoa(maxAge)}
				if config.GetHSTSIncludeSubDomains() {
					hsts = append(hsts, "includeSubDomains")
				}
				if config.GetHSTSPreload() {
					hsts = append(hsts, "preload")
				}
				w.Header().Set("Strict-Transport-Security", strings.Join(hsts, "; "))
			}
		}

		w.Header().Set("Cross-Origin-Opener-Policy", crossOriginOpenerPolicy)
		w.Header().Set("Cross-Origin-Resource-Policy", crossOriginResourcePolicy)
		w.Header().Set("Cross-Origin-Embedder-Policy", crossOriginEmbedderPolicy)

		next(w, r)
	}
}
