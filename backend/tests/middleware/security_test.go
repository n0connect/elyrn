package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"elyrn/internal/middleware"
	"elyrn/tests/testutil"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify security headers
	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	}

	for header, expectedValue := range headers {
		actualValue := rr.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Header %s = %q, want %q", header, actualValue, expectedValue)
		}
	}

	// Verify handler was called
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
}

func TestSecurityHeadersMiddleware_PermissionsPolicy(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	req := httptest.NewRequest("GET", "/api/v2/conversations", nil)

	rr := httptest.NewRecorder()

	testHandler := middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify Permissions-Policy header
	permissionsPolicy := rr.Header().Get("Permissions-Policy")
	if permissionsPolicy == "" {
		t.Error("Permissions-Policy header should be set")
	}

	// Whitelist: every powerful feature must be denied
	for _, feature := range []string{"camera=()", "microphone=()", "geolocation=()", "payment=()", "usb=()", "browsing-topics=()", "interest-cohort=()"} {
		if !strings.Contains(permissionsPolicy, feature) {
			t.Errorf("Permissions-Policy %q does not deny %s", permissionsPolicy, feature)
		}
	}
}

// API responses are data, never documents: if one were ever rendered (sniffing, a proxy
// error page, a mistaken navigation) it may load and run nothing, and no cache keeps it.
func TestSecurityHeadersMiddleware_APIResponsesAreInertAndUncached(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	rr := httptest.NewRecorder()
	middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})(rr, httptest.NewRequest("GET", "/api/v2/me", nil))

	want := map[string]string{
		"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
		"Cache-Control":                "no-store",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
	}
	for header, value := range want {
		if got := rr.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

// The backend never sends Strict-Transport-Security, whatever the mode, the HSTS settings and
// what a listed proxy says about the protocol: nginx is its one source (nginx-hsts.sh).
func TestSecurityHeadersMiddleware_NeverSendsHSTS(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("HSTS_MAX_AGE", "31536000")
	t.Setenv("HSTS_INCLUDE_SUBDOMAINS", "true")
	t.Setenv("HSTS_PRELOAD", "true")
	t.Setenv("TRUSTED_PROXIES", "192.0.2.10")
	middleware.LoadTrustedProxies()
	t.Cleanup(middleware.LoadTrustedProxies)

	for name, configure := range map[string]func(*http.Request){
		"plain": func(*http.Request) {},
		"https from a listed proxy": func(r *http.Request) {
			r.RemoteAddr = "192.0.2.10:4000"
			r.Header.Set("X-Forwarded-Proto", "https")
		},
		"https from anyone": func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") },
	} {
		r := httptest.NewRequest(http.MethodGet, "/api/v2/me", nil)
		configure(r)
		rr := httptest.NewRecorder()
		middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})(rr, r)
		if got := rr.Header().Values("Strict-Transport-Security"); len(got) != 0 {
			t.Errorf("%s: the backend sent Strict-Transport-Security %q", name, got)
		}
	}
}

// The cross-origin headers are fixed, the same three nginx sends: the settings of earlier
// releases (SEC_HEADER_*) can neither turn them off nor change them, in any mode.
func TestSecurityHeadersMiddleware_CrossOriginHeadersAreFixed(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	want := map[string]string{
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cross-Origin-Embedder-Policy": "require-corp",
	}
	for _, setting := range []string{"off", "disabled", "unsafe-none", "cross-origin"} {
		for _, mode := range []string{"development", "production"} {
			t.Setenv("APP_ENV", mode)
			t.Setenv("SEC_HEADER_COOP", setting)
			t.Setenv("SEC_HEADER_CORP", setting)
			t.Setenv("SEC_HEADER_COEP", setting)
			rr := httptest.NewRecorder()
			middleware.SecurityHeadersMiddleware(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})(rr, httptest.NewRequest("GET", "/api/v2/me", nil))
			for header, value := range want {
				if got := rr.Header().Values(header); len(got) != 1 || got[0] != value {
					t.Errorf("%s with SEC_HEADER_*=%s: %s = %q, want exactly %q", mode, setting, header, got, value)
				}
			}
		}
	}
}
