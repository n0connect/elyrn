package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"elyrn/internal/middleware"
	"elyrn/tests/testutil"

	"github.com/jackc/pgx/v5/pgconn"
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

// panicCanary marks a panic value's text: it must never reach the log
const panicCanary = "elyrn-panic-canary-10.0.0.7-secret"

// panicLine is the recovered panic's log line, as the logger writes it (one line, newlines escaped)
var panicLine = regexp.MustCompile(`handler panic recovered: [^\n]*`)

// stackArgumentWords and stackPCOffsets are what a raw stack carries beyond function names and
// source lines: a frame's argument words ("(0xc000...", "{0x4a...", "...)") and pc offsets
var (
	stackArgumentWords = regexp.MustCompile(`\(0x|\{0x|\(\.\.\.\)|0x[0-9a-f]+\?`)
	stackPCOffsets     = regexp.MustCompile(` \+0x[0-9a-f]+`)
)

// capturedLog is the standard logger's output while a test runs.
type capturedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *capturedLog) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

func (c *capturedLog) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// captureLog sends the standard logger to a buffer until the test ends.
func captureLog(t testing.TB) *capturedLog {
	t.Helper()
	captured := &capturedLog{}
	previous := log.Writer()
	log.SetOutput(captured)
	t.Cleanup(func() { log.SetOutput(previous) })
	return captured
}

// panicked runs a handler that panics with value behind Recover and returns what it logged.
func panicked(t testing.TB, value any) string {
	t.Helper()
	captured := captureLog(t)
	middleware.Recover(func(http.ResponseWriter, *http.Request) { panic(value) })(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	return captured.String()
}

// expectSafePanicLine insists a recovered panic's log holds no text of the value (the canary),
// and that a line logged for it carries only function names and source lines in its stack.
func expectSafePanicLine(t testing.TB, logged string) {
	t.Helper()
	if strings.Contains(logged, panicCanary) {
		t.Fatalf("the panic value's text reached the log: %q", logged)
	}
	line := panicLine.FindString(logged)
	if line == "" {
		return
	}
	if stackArgumentWords.MatchString(line) || stackPCOffsets.MatchString(line) {
		t.Fatalf("the stack carries argument words or pc offsets: %q", line)
	}
}

type canaryStringer string

func (s canaryStringer) String() string { return string(s) }

// The log of a recovered panic names the value's Go type (and a database error's class), never
// its text, and keeps the stack as function names and source lines only.
func TestRecover_LogsTheTypeNeverTheValue(t *testing.T) {
	cases := []struct {
		value any
		want  string
	}{
		{panicCanary, "type=string"},
		{errors.New(panicCanary), "type=*errors.errorString"},
		{fmt.Errorf("wrapped: %w", errors.New(panicCanary)), "type=*fmt.wrapError"},
		{canaryStringer(panicCanary), "type=middleware.canaryStringer"},
		{&pgconn.PgError{Code: "23505", Message: panicCanary, Detail: panicCanary}, "type=*pgconn.PgError class=database: SQLSTATE 23505"},
	}
	for _, c := range cases {
		logged := panicked(t, c.value)
		expectSafePanicLine(t, logged)
		line := panicLine.FindString(logged)
		if !strings.Contains(line, c.want) || !strings.Contains(line, "stack=") ||
			!strings.Contains(line, "elyrn/internal/middleware.Recover") {
			t.Fatalf("panic %T logged %q, want %q and a stack through Recover", c.value, line, c.want)
		}
	}
}
