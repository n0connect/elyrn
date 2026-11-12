package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"elyrn/internal/contract"
	"elyrn/internal/models"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzRouteChain$' -fuzztime 60s ./internal/server

const (
	// routeHost is the host every fuzzed request is addressed to
	routeHost = "elyrn.test"
	// routePeer is an ordinary, untrusted client address
	routePeer = "192.0.2.10:40000"
)

// FuzzRouteChain runs arbitrary requests through the production chain (Recover, security
// headers, CORS, same-origin writes, the gate) with a probe in place of the handler: nothing
// panics, nothing answers 5xx, every refusal is a registered answer, and the probe only ever
// runs with what the gate admitted. A request the chain refuses gets the same status and body
// from the complete mux (NewMux, real handlers behind it), except that the mux may first
// redirect a path it cleans; so routing and the gate never disagree about what exists. OPTIONS
// is the CORS preflight, answered before the gate.
func FuzzRouteChain(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	mux := NewMux()
	conversation := models.PathConversations + "/3b241101-e2bb-4255-8caf-4136c566a962"
	for _, seed := range []struct{ method, target, contentType, body string }{
		{http.MethodGet, models.PathPoWChallenge, "", ""},
		{http.MethodPost, models.PathLogin, utils.MIMEJSON, `{"auth_key":"x"}`},
		{http.MethodPost, models.PathLogin, "text/plain", `{}`},
		{http.MethodHead, models.PathRegister, "", ""},
		{http.MethodGet, conversation + "/messages?after=1&before=2", "", ""},
		{http.MethodGet, conversation + "/../messages", "", ""},
		{http.MethodGet, models.PathConversations + "//messages", "", ""},
		{http.MethodDelete, conversation + "/notes/not-a-uuid", "", ""},
		{http.MethodOptions, models.PathMe, "", ""},
		{"PATCH", models.PathMe, utils.MIMEJSON, `{}`},
		{http.MethodGet, "/api/v2/unknown", "", ""},
		{http.MethodGet, "/", "", ""},
		{http.MethodGet, models.PathHealth + "/", "", ""},
	} {
		f.Add(seed.method, seed.target, seed.contentType, seed.body)
	}
	f.Fuzz(func(t *testing.T, method, target, contentType, body string) {
		request := func() *http.Request {
			r, err := http.NewRequest(method, "http://"+routeHost+target, strings.NewReader(body))
			if err != nil {
				return nil
			}
			r.RemoteAddr = routePeer
			if contentType != "" {
				r.Header.Set(utils.HeaderContentType, contentType)
			}
			return r
		}
		r := request()
		if r == nil {
			return // not a request net/http would hand a handler
		}
		reached := false
		rec := httptest.NewRecorder()
		public(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := contract.InputOf(r); !ok {
				t.Fatalf("%s %q reached the handler without the gate's input", method, target)
			}
			reached = true
		})(rec, r)
		if reached {
			return // admitted: the real handler would need the database
		}
		if method == http.MethodOptions {
			// CORS answers every preflight before the gate (204, no body; a foreign Origin
			// would get E_CROSS_ORIGIN, see FuzzCORS); the mux runs the chain on its routes only
			if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
				t.Fatalf("OPTIONS %q answered %d %q", target, rec.Code, rec.Body.String())
			}
			return
		}
		if _, ok := testutil.RegisteredAnswer(rec); !ok || rec.Code >= http.StatusInternalServerError {
			t.Fatalf("%s %q refused with the unregistered answer %d %q", method, target, rec.Code, rec.Body.String())
		}
		viaMux := httptest.NewRecorder()
		mux.ServeHTTP(viaMux, request())
		redirected := viaMux.Code >= http.StatusMultipleChoices && viaMux.Code < http.StatusBadRequest
		if !redirected && (viaMux.Code != rec.Code || viaMux.Body.String() != rec.Body.String()) {
			t.Fatalf("%s %q: the chain answered %d %q, the mux %d %q", method, target, rec.Code, rec.Body.String(), viaMux.Code, viaMux.Body.String())
		}
	})
}
