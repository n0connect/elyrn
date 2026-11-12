package apperr

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"
	"unicode/utf8"

	"elyrn/internal/utils"
)

// Run one with: go test -tags test -run '^$' -fuzz '^FuzzWriteError$' -fuzztime 60s ./internal/apperr

const (
	// maxWrapDepth bounds how deep a fuzzed error chain is wrapped
	maxWrapDepth = 8
	// noSentinel: a fuzzed sentinel index at or past len(sentinels) wraps no sentinel
	noSentinel = 0xff
)

// expectEntry fails unless rec holds exactly e's wire answer (status, body, content type).
func expectEntry(t *testing.T, rec *httptest.ResponseRecorder, e entry, what string) {
	t.Helper()
	want := httptest.NewRecorder()
	send(want, e)
	if rec.Code != want.Code || rec.Body.String() != want.Body.String() ||
		rec.Header().Get(utils.HeaderContentType) != want.Header().Get(utils.HeaderContentType) {
		t.Fatalf("%s: answered %d %q, want %s (%d %q)", what, rec.Code, rec.Body.String(), e.id, want.Code, want.Body.String())
	}
}

// FuzzWriteError builds arbitrary error chains (a free-text cause, optionally around one
// sentinel, wrapped to any depth, optionally joined): the answer is exactly the sentinel's
// registered one, or Internal; the error's own text never reaches the client.
func FuzzWriteError(f *testing.F) {
	for i := range sentinels {
		f.Add("cause", uint8(i), uint8(1), false)
	}
	f.Add("pq: password authentication failed for user \"postgres\" host 10.0.0.5", uint8(noSentinel), uint8(0), false)
	f.Add("Internal server error", uint8(noSentinel), uint8(3), true)
	f.Add("", uint8(0), uint8(maxWrapDepth), true)
	f.Add("\x00\xff\n", uint8(len(sentinels)), uint8(2), false)
	f.Fuzz(func(t *testing.T, cause string, sentinel, depth uint8, join bool) {
		err := errors.New(cause)
		wantCode, wrapped := Internal, int(sentinel) < len(sentinels)
		if wrapped {
			err = fmt.Errorf("%s: %w", cause, sentinels[sentinel].err)
			wantCode = sentinels[sentinel].code
		}
		for range int(depth) % (maxWrapDepth + 1) {
			err = fmt.Errorf("%s: %w", cause, err)
		}
		if join {
			err = errors.Join(errors.New(cause), err)
		}
		rec := httptest.NewRecorder()
		WriteError(rec, "fuzz", err)
		expectEntry(t, rec, registry[wantCode], fmt.Sprintf("sentinel %d", sentinel))
	})
}

// FuzzWriteCode: any code value, registered or not, answers a registered entry (an unregistered
// one is Internal), never an empty status; WriteCause answers the code and not its cause.
func FuzzWriteCode(f *testing.F) {
	f.Add(int(MethodNotAllowed), "cause")
	f.Add(int(Internal), "")
	f.Add(0, "x")
	f.Add(-1, "x")
	f.Add(int(Internal)+1, "\x00")
	f.Fuzz(func(t *testing.T, code int, cause string) {
		want, ok := registry[Code(code)]
		if !ok {
			want = registry[Internal]
		}
		rec := httptest.NewRecorder()
		Write(rec, "fuzz", Code(code))
		expectEntry(t, rec, want, fmt.Sprintf("Write(%d)", code))
		rec = httptest.NewRecorder()
		WriteCause(rec, "fuzz", Code(code), errors.New(cause))
		expectEntry(t, rec, want, fmt.Sprintf("WriteCause(%d)", code))
	})
}

// FuzzEdgeBody: an edge answer's body is always one JSON object with success false; its message
// and code read back exactly (text that is not UTF-8 is replaced, never passed through raw).
func FuzzEdgeBody(f *testing.F) {
	for _, a := range EdgeAnswers {
		f.Add(a.ID, a.Status, a.Sentence)
	}
	f.Add("E_\"quoted\"", 0, "<script>")
	f.Add("\xff", -1, "\x00\n")
	f.Fuzz(func(t *testing.T, id string, status int, sentence string) {
		body := EdgeAnswer{ID: id, Status: status, Sentence: sentence}.Body()
		var got edgeBody
		if err := json.Unmarshal([]byte(body), &got); err != nil || got.Success {
			t.Fatalf("body %q: %v", body, err)
		}
		if utf8.ValidString(id) && utf8.ValidString(sentence) && (got.Code != id || got.Message != sentence) {
			t.Fatalf("body %q does not read back %q / %q", body, id, sentence)
		}
		if !utf8.ValidString(body) {
			t.Fatalf("body %q is not UTF-8", body)
		}
	})
}
