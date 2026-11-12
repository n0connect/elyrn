package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"elyrn/internal/middleware"
	"elyrn/tests/testutil"
)

// A handler that panics answers 500 with the generic sentence; the panic never reaches net/http
// (which would log the peer address and drop the connection).
func TestRecover_PanicAnswersInternalServerError(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	handler := middleware.Recover(func(w http.ResponseWriter, r *http.Request) {
		panic("handler failed")
	})
	rr := httptest.NewRecorder()
	handler(rr, httptest.NewRequest("GET", "/api/v2/conversations", nil))

	if rr.Code != http.StatusInternalServerError || rr.Body.String() != "Internal server error\n" {
		t.Fatalf("got %d %q, want 500 %q", rr.Code, rr.Body.String(), "Internal server error\n")
	}
}

// The event stream needs http.Flusher: Recover must hand the handler the writer it was given.
func TestRecover_KeepsTheFlusher(t *testing.T) {
	flushed := false
	handler := middleware.Recover(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("the writer behind Recover is not an http.Flusher")
		}
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		flushed = true
	})
	rr := httptest.NewRecorder()
	handler(rr, httptest.NewRequest("GET", "/api/v2/events", nil))
	if !flushed || !rr.Flushed || rr.Code != http.StatusOK {
		t.Fatalf("flushed=%v recorder.Flushed=%v status=%d", flushed, rr.Flushed, rr.Code)
	}
}

// http.ErrAbortHandler is net/http's own "abort this response quietly": it must pass through.
func TestRecover_ReraisesErrAbortHandler(t *testing.T) {
	handler := middleware.Recover(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want http.ErrAbortHandler re-raised", recovered)
		}
	}()
	handler(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v2/events", nil))
}
