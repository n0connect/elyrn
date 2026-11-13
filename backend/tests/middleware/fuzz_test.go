package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/internal/middleware"
	"elyrn/tests/testutil"
)

// Run one with: go test -tags test -run '^$' -fuzz '^FuzzClientKey$' -fuzztime 60s ./tests/middleware

const (
	// fuzzProxies is the trusted-proxy list the fuzzed requests are judged against
	fuzzProxies = "10.0.0.1, 192.168.0.0/16, fd00::/8"
	// fuzzOrigins is the origin whitelist the fuzzed requests are judged against
	fuzzOrigins = "https://elyrn.example,http://localhost:3000"
	// the request headers the middleware reads, and the CORS answer header it writes
	headerXFF       = "X-Forwarded-For"
	headerXRealIP   = "X-Real-IP"
	headerProto     = "X-Forwarded-Proto"
	headerOrigin    = "Origin"
	headerFetchSite = "Sec-Fetch-Site"
	headerACAO      = "Access-Control-Allow-Origin"
	fetchSameOrigin = "same-origin"
	// clientKeyHexLen: a client key is 16 bytes of HMAC, in hex
	clientKeyHexLen = 32
)

// fuzzTrusted is fuzzProxies parsed with net/netip, independently of the middleware.
var fuzzTrusted = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fd00::/8"),
}

// trustedPeer is the oracle: remote (host[:port], or a bare address) is a listed proxy. A zone
// or anything net/netip refuses is never trusted.
func trustedPeer(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return false
	}
	for _, prefix := range fuzzTrusted {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// setupFuzzMiddleware configures the proxies and origins once for a fuzz target.
func setupFuzzMiddleware(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Setenv("TRUSTED_PROXIES", fuzzProxies)
	f.Setenv("ALLOWED_ORIGINS", fuzzOrigins)
	middleware.ResetTrustedProxiesForTesting()
	middleware.ResetAllowedOriginsForTesting()
	f.Cleanup(func() {
		testutil.TeardownTestEnv(f)
		middleware.ResetTrustedProxiesForTesting()
		middleware.ResetAllowedOriginsForTesting()
	})
}

// FuzzClientKey: an untrusted peer can never choose its own client key or claim HTTPS: its
// forwarded headers change nothing. Behind a trusted proxy the client is the peer or a forwarded
// address, never a listed proxy, and the key is always 32 lowercase hex characters.
func FuzzClientKey(f *testing.F) {
	setupFuzzMiddleware(f)
	for _, seed := range [][4]string{
		{"203.0.113.10:4000", "198.51.100.20", "198.51.100.30", "https"},
		{"10.0.0.1:4000", "198.51.100.20, 10.0.0.1", "", "https"},
		{"192.168.1.1:4000", "10.0.0.1, 192.168.4.4", "198.51.100.30", "HTTPS"},
		{"[fd00::1]:4000", "2001:db8::1, fd00::2", "", ""},
		{"[::ffff:10.0.0.1]:4000", "1.2.3.4", "", "https"},
		{"[fe80::1%eth0]:4000", "1.2.3.4", "", "https"},
		{"10.0.0.1", " 1.2.3.4 ,", "garbage", "https "},
		{"", "", "", ""},
		{"not an address", "\x00", "\xff", "\n"},
	} {
		f.Add(seed[0], seed[1], seed[2], seed[3])
	}
	f.Fuzz(func(t *testing.T, remote, xff, realIP, proto string) {
		bare := httptest.NewRequest(http.MethodGet, "/", nil)
		bare.RemoteAddr = remote
		forwarded := bare.Clone(bare.Context())
		forwarded.Header.Set(headerXFF, xff)
		forwarded.Header.Set(headerXRealIP, realIP)
		forwarded.Header.Set(headerProto, proto)

		key, err := middleware.ClientKey(forwarded)
		if err != nil || len(key) != clientKeyHexLen || strings.Trim(key, "0123456789abcdef") != "" {
			t.Fatalf("client key %q (%v)", key, err)
		}
		client := middleware.ClientIP(forwarded)
		if !trustedPeer(remote) {
			bareKey, _ := middleware.ClientKey(bare)
			if client != middleware.ClientIP(bare) || key != bareKey || middleware.IsRequestHTTPS(forwarded) {
				t.Fatalf("untrusted peer %q chose client %q via headers", remote, client)
			}
			return
		}
		if client != middleware.ClientIP(bare) && trustedPeer(client) {
			t.Fatalf("a listed proxy %q became the client of %q", client, remote)
		}
	})
}

// FuzzCORS: an Origin is echoed only when it is exactly one listed origin; a foreign preflight
// and a state-changing request without same-origin proof are refused with E_CROSS_ORIGIN; and
// a write reaches the handler only with Sec-Fetch-Site same-origin, or without that header and
// with no Origin or a listed one.
func FuzzCORS(f *testing.F) {
	setupFuzzMiddleware(f)
	listed := map[string]bool{}
	for _, origin := range strings.Split(fuzzOrigins, ",") {
		listed[origin] = true
	}
	for _, seed := range [][3]string{
		{http.MethodPost, "https://elyrn.example", fetchSameOrigin},
		{http.MethodPost, "https://elyrn.example", ""},
		{http.MethodPost, "https://elyrn.example.evil.example", ""},
		{http.MethodOptions, "http://localhost:3000", ""},
		{http.MethodOptions, "http://localhost:3000.evil.example", ""},
		{http.MethodDelete, "", "same-site"},
		{http.MethodGet, "null", "cross-site"},
		{"post", "HTTPS://ELYRN.EXAMPLE", ""},
	} {
		f.Add(seed[0], seed[1], seed[2])
	}
	f.Fuzz(func(t *testing.T, method, origin, fetchSite string) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Method = method
		if origin != "" {
			r.Header.Set(headerOrigin, origin)
		}
		if fetchSite != "" {
			r.Header.Set(headerFetchSite, fetchSite)
		}
		reached := false
		rec := httptest.NewRecorder()
		middleware.CORSMiddleware(middleware.SameOriginWritesMiddleware(func(http.ResponseWriter, *http.Request) {
			reached = true
		}))(rec, r)

		echoed := rec.Header().Get(headerACAO)
		allowed := listed[r.Header.Get(headerOrigin)]
		if echoed != "" && (!allowed || echoed != r.Header.Get(headerOrigin)) {
			t.Fatalf("origin %q echoed as %q", origin, echoed)
		}
		writes := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
		site := r.Header.Get(headerFetchSite)
		proven := site == fetchSameOrigin || (site == "" && (r.Header.Get(headerOrigin) == "" || allowed))
		if reached && writes && !proven {
			t.Fatalf("%s from origin %q (fetch site %q) reached the handler", method, origin, fetchSite)
		}
		if !reached && rec.Code != http.StatusNoContent && !testutil.IsAnswer(rec, apperr.CrossOrigin) {
			t.Fatalf("%s from origin %q refused with %d %q", method, origin, rec.Code, rec.Body.String())
		}
	})
}

// fuzzStringer is a panic value whose text is computed (as a panicking fmt.Stringer would be)
type fuzzStringer string

func (s fuzzStringer) String() string { return string(s) }

// panic kinds FuzzRecover throws, one per run
const (
	panicString = iota
	panicError
	panicStringer
	panicInt
	panicNil
	panicAbort
	panicKinds
)

// FuzzRecover: a handler that panics with any value answers exactly the registered E_PANIC
// (500, the generic sentence; the panic's text never reaches the client), except
// http.ErrAbortHandler, which is re-raised for net/http. The log never holds the value's text
// (each text carries panicCanary), and its stack carries no argument word or pc offset.
func FuzzRecover(f *testing.F) {
	for kind := range panicKinds {
		f.Add(uint8(kind), "handler failed: secret 10.0.0.7")
	}
	f.Add(uint8(panicString), "")
	f.Add(uint8(panicError), "\x00\n\xff")
	f.Fuzz(func(t *testing.T, kind uint8, text string) {
		text = panicCanary + text
		captured := captureLog(t)
		var value any
		switch kind % panicKinds {
		case panicString:
			value = text
		case panicError:
			value = errors.New(text)
		case panicStringer:
			value = fuzzStringer(text)
		case panicInt:
			value = len(text)
		case panicNil:
			value = nil
		case panicAbort:
			value = http.ErrAbortHandler
		}
		rec := httptest.NewRecorder()
		reraised := func() (out any) {
			defer func() { out = recover() }()
			middleware.Recover(func(http.ResponseWriter, *http.Request) { panic(value) })(rec, httptest.NewRequest(http.MethodGet, "/", nil))
			return nil
		}()
		if value == http.ErrAbortHandler {
			if reraised != http.ErrAbortHandler {
				t.Fatalf("ErrAbortHandler was not re-raised (got %v)", reraised)
			}
			return
		}
		if reraised != nil || !testutil.IsAnswer(rec, apperr.Panic) {
			t.Fatalf("panic %s answered %d %q (re-raised %v)", fmt.Sprint(value), rec.Code, rec.Body.String(), reraised)
		}
		expectSafePanicLine(t, captured.String())
	})
}
