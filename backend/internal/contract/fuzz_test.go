package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"
)

// One fuzz target per pattern and validator pair: whatever a pattern accepts is canonical,
// so decoding it and encoding it again gives the input back, and nothing panics.
// Run one with: go test -tags test -run '^$' -fuzz '^FuzzPatternUUIDv4$' -fuzztime 30s ./internal/contract

// fuzzBase64 asserts that every accepted value re-encodes to itself (and decodes to a size
// inside [minBytes, maxBytes]).
func fuzzBase64(f *testing.F, p *Pattern, seeds ...string) {
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s || len(s) < p.MinLen || len(s) > p.MaxLen {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func base64Seeds(t testing.TB, p *Pattern) []string {
	valid := exampleString(t, p)
	return []string{valid, valid + "A", valid[:len(valid)-1], valid[:len(valid)-1] + "B", strings.ToUpper(valid), valid + "=", "", "\n" + valid}
}

func FuzzPatternUUIDv4(f *testing.F) {
	for _, seed := range []string{uuid.NewString(), strings.ToUpper(uuid.NewString()), uuid.Nil.String(), "{" + uuid.NewString() + "}", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternUUIDv4.Accepts(s) {
			return
		}
		id, err := uuid.Parse(s)
		if err != nil || id.String() != s || id.Version() != 4 || id.Variant() != uuid.RFC4122 {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

func FuzzPatternKey32(f *testing.F) { fuzzBase64(f, patternKey32, base64Seeds(f, patternKey32)...) }
func FuzzPatternInviteToken(f *testing.F) {
	fuzzBase64(f, patternInviteToken, base64Seeds(f, patternInviteToken)...)
}
func FuzzPatternRoomCard(f *testing.F) {
	fuzzBase64(f, patternRoomCard, base64Seeds(f, patternRoomCard)...)
}
func FuzzPatternRoomVault(f *testing.F) {
	fuzzBase64(f, patternRoomVault, base64Seeds(f, patternRoomVault)...)
}
func FuzzPatternRoomRole(f *testing.F) {
	fuzzBase64(f, patternRoomRole, base64Seeds(f, patternRoomRole)...)
}

// FuzzPatternFilePart: a part is long, so the fuzzer mostly mutates the seeds' edges; whatever it
// accepts decodes to exactly one sealed part and re-encodes to itself.
func FuzzPatternFilePart(f *testing.F) {
	fuzzBase64(f, patternFilePart, base64Seeds(f, patternFilePart)...)
}

// FuzzPatternPartQuery: a part number's text either parses into an integer that formats back to
// it, or parseQuery refuses it at the integer step.
func FuzzPatternPartQuery(f *testing.F) {
	for _, seed := range []string{"0", "1", "01", "399", "400", "999", "1000", "-0", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternPartQuery.Accepts(s) {
			return
		}
		if v, ok := parseInteger(s); ok && strconv.FormatInt(v, 10) != s {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

// FuzzGateFileRead: whatever conversation id, file id and query a file read carries, an admitted
// request names exactly those two ids, each at its own position (none at the note's), and one
// part number in range, written canonically.
func FuzzGateFileRead(f *testing.F) {
	for _, seed := range []struct{ conversation, file, query string }{
		{exampleConversation, exampleFile, "part=0"},
		{exampleConversation, exampleFile, "part=" + strconv.FormatInt(maxFilePart, 10)},
		{exampleConversation, exampleFile, "part=" + strconv.FormatInt(maxFilePart+1, 10)},
		{exampleConversation, exampleFile, ""},
		{exampleConversation, exampleFile, "part=0&part=1"},
		{exampleFile, exampleConversation, "part=01"},
		{strings.ToUpper(exampleConversation), exampleFile, "part=0"},
		{exampleConversation, exampleNote + "/x", "part=0"},
	} {
		f.Add(seed.conversation, seed.file, seed.query)
	}
	f.Fuzz(func(t *testing.T, conversation, file, query string) {
		target := models.PathConversations + "/" + conversation + "/" + models.SubFiles + "/" + file
		if query != "" {
			target += "?" + query
		}
		r, err := http.NewRequest(http.MethodGet, "http://"+gateHost+target, nil)
		if err != nil {
			return // not a request net/http would hand a handler
		}
		in := admittedByGate(t, r, strconv.Quote(target))
		if in == nil {
			return
		}
		part, ok := in.Query(models.QueryPart)
		if in.Op.ID != OpFileRead || in.PathID(PathConversation).String() != conversation || in.PathID(PathFile).String() != file ||
			in.PathID(PathNote) != uuid.Nil || !ok || !rangeFilePart.Accepts(part) || models.QueryPart+"="+strconv.FormatInt(part, 10) != r.URL.RawQuery {
			t.Fatalf("%q admitted as %+v", target, in)
		}
	})
}
func FuzzPatternMessage(f *testing.F) {
	fuzzBase64(f, patternMessage, exampleString(f, patternMessage), roomBlob(f, utils.RoomMessageMagic, 2), roomBlob(f, utils.RoomNoteMagic, 1))
}
func FuzzPatternNote(f *testing.F) {
	fuzzBase64(f, patternNote, exampleString(f, patternNote), roomBlob(f, utils.RoomMessageMagic, 1), roomBlob(f, utils.RoomNoteMagic, 2))
}

// fuzzHex: an accepted challenge or salt is lowercase hex of its exact size.
func fuzzHex(f *testing.F, p *Pattern) {
	valid := exampleString(f, p)
	for _, seed := range []string{valid, strings.ToUpper(valid), valid + "0", valid[1:], ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		raw, err := hex.DecodeString(s)
		if err != nil || hex.EncodeToString(raw) != s || len(s) != p.MaxLen {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func FuzzPatternChallenge(f *testing.F) { fuzzHex(f, patternChallenge) }
func FuzzPatternSalt(f *testing.F)      { fuzzHex(f, patternSalt) }

// fuzzDecimal: an accepted decimal re-formats to itself within bitSize bits.
func fuzzDecimal(f *testing.F, p *Pattern, bitSize int) {
	for _, seed := range []string{"0", "1", "007", "-1", "+1", "1e3", "18446744073709551615", "18446744073709551616", "9223372036854775808", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		v, err := strconv.ParseUint(s, 10, bitSize)
		if err != nil || strconv.FormatUint(v, 10) != s {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func FuzzPatternSolution(f *testing.F) { fuzzDecimal(f, patternSolution, 64) }

// FuzzPatternSeqQuery: a page cursor's text either parses into an int64 that formats back to
// it, or parseQuery refuses it at the integer step.
func FuzzPatternSeqQuery(f *testing.F) {
	for _, seed := range []string{"0", "1", "01", "9223372036854775807", "9223372036854775808", "-0", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternSeqQuery.Accepts(s) {
			return
		}
		if v, ok := parseInteger(s); ok && strconv.FormatInt(v, 10) != s {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

// FuzzIntegerLiteral: a JSON integer the walk admits formats back to its literal.
func FuzzIntegerLiteral(f *testing.F) {
	for _, seed := range []string{"0", "-0", "1", "-1", "01", "1.0", "1e2", "9223372036854775807", "-9223372036854775808", "9223372036854775808"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := parseInteger(s); ok && strconv.FormatInt(v, 10) != s {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

// FuzzPatternPendingToken: an accepted pending token is empty or three non-empty base64url
// segments within the parser's bound (its signature is the handler's to verify).
func FuzzPatternPendingToken(f *testing.F) {
	for _, seed := range []string{examplePendingToken, "", "a.b", "a..c", "a.b.c.d", "a.b.c=", strings.Repeat("a", 1025)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternPendingToken.Accepts(s) || s == "" {
			return
		}
		parts := strings.Split(s, ".")
		if len(parts) != 3 || len(s) > patternPendingToken.MaxLen {
			t.Fatalf("accepted %q", s)
		}
		for _, part := range parts {
			if part == "" || !utils.IsBase64URL(part) {
				t.Fatalf("accepted %q", s)
			}
		}
	})
}

// FuzzGateLoginBody: whatever login body the gate admits binds to LoginRequest, whose key is
// canonical base64url of 32 bytes, and re-encodes to the same bytes; nothing panics.
func FuzzGateLoginBody(f *testing.F) {
	valid := `{"auth_key":"` + exampleString(f, patternKey32) + `"}`
	for _, seed := range []string{valid, valid + valid, `{"auth_key":null}`, "null", "", `{"auth_key":"x","auth_key":"y"}`, strings.Repeat("[", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, models.PathLogin, strings.NewReader(body))
		r.Header.Set(utils.HeaderContentType, jsonContentType)
		var in *Input
		Gate(func(w http.ResponseWriter, r *http.Request) { in, _ = InputOf(r) })(httptest.NewRecorder(), r)
		if in == nil {
			return
		}
		var req models.LoginRequest
		if err := in.Bind(&req); err != nil || !patternKey32.Accepts(req.AuthKey) {
			t.Fatalf("admitted %q", body)
		}
		raw, ok := utils.DecodeExact(req.AuthKey, identity.KeySize)
		if !ok || base64.RawURLEncoding.EncodeToString(raw) != req.AuthKey {
			t.Fatalf("admitted the non-canonical %q", body)
		}
	})
}

// gateHost is the host every fuzzed request is addressed to (the gate never reads it)
const gateHost = "elyrn.test"

// addGateSeeds seeds FuzzGateRequest with every operation's canonical request and the hostile
// shapes the gate must refuse: duplicate and case-folded keys, escapes, deep nesting, trailing
// values, wrong content types, unknown lengths, percent-encoded paths and malformed queries.
func addGateSeeds(f *testing.F) {
	forEachOp(func(e *Endpoint, op *Op) {
		path := examplePath(e.Template)
		body := ""
		if op.Body != nil {
			body = buildBody(f, op.Body.Fields, "", mutation{})
		}
		f.Add(op.Method, path, jsonContentType, body, false)
		f.Add(op.Method, path+"?after=1", jsonContentType, body, true)
		if query := canonicalQuery(op); query != "" {
			f.Add(op.Method, path+"?"+query, jsonContentType, body, false)
		}
	})
	key := exampleString(f, patternKey32)
	messages := models.PathConversations + "/" + exampleConversation + "/" + models.SubMessages
	for _, seed := range []struct{ method, target, contentType, body string }{
		{http.MethodPost, models.PathLogin, jsonContentType, `{"auth_key":"` + key + `","auth_key":"` + key + `"}`},
		{http.MethodPost, models.PathLogin, jsonContentType, `{"AUTH_KEY":"` + key + `"}`},
		{http.MethodPost, models.PathLogin, jsonContentType, `{"auth\u005fkey":"` + key + `"}`},
		{http.MethodPost, models.PathLogin, jsonContentType, `{"auth_key":"` + key + `"} {}`},
		{http.MethodPost, models.PathLogin, jsonContentType, `{"auth_key":"` + key + "\xff" + `"}`},
		{http.MethodPost, models.PathLogin, jsonContentType + "; charset=utf-8", `{"auth_key":"` + key + `"}`},
		{http.MethodPost, models.PathLogin, "APPLICATION/JSON", `{"auth_key":"` + key + `"}`},
		{http.MethodPost, models.PathLogin, jsonContentType, strings.Repeat(`{"a":`, 64)},
		{http.MethodPost, models.PathRegister, jsonContentType, `{"pow":{"pow":{}}}`},
		{http.MethodPost, models.PathRegister, "", ""},
		{http.MethodGet, messages + "?after=1&after=2", "", ""},
		{http.MethodGet, messages + "?after=01", "", ""},
		{http.MethodGet, messages + "?before=0", "", ""},
		{http.MethodGet, messages + "?after=-1", "", ""},
		{http.MethodGet, messages + "?after=9223372036854775808", "", ""},
		{http.MethodGet, messages + "?after", "", ""},
		{http.MethodGet, strings.ToUpper(messages), "", ""},
		{http.MethodGet, models.PathConversations + "/%33b241101-e2bb-4255-8caf-4136c566a962/messages", "", ""},
		{http.MethodGet, models.PathConversations + "/" + strings.ToUpper(exampleConversation) + "/messages", "", ""},
		{http.MethodHead, models.PathLogin, "", ""},
		{"BREW", models.PathMe, "", ""},
		{http.MethodGet, "/", "", "\x00"},
	} {
		f.Add(seed.method, seed.target, seed.contentType, seed.body, false)
	}
}

// FuzzGateRequest runs arbitrary requests through the gate. A refusal is always a registered
// answer below 500; an admitted request is exactly one table operation on its own path, its
// query values are declared and in range, its body is within the bound and passes the table
// again, and its JSON re-encoded (as any client library would) is still admitted.
func FuzzGateRequest(f *testing.F) {
	addGateSeeds(f)
	f.Fuzz(func(t *testing.T, method, target, contentType, body string, unknownLength bool) {
		r, err := http.NewRequest(method, "http://"+gateHost+target, strings.NewReader(body))
		if err != nil {
			return // not a request net/http would hand a handler
		}
		if contentType != "" {
			r.Header.Set(utils.HeaderContentType, contentType)
		}
		if unknownLength {
			r.ContentLength = -1
		}
		in := admittedByGate(t, r, method+" "+strconv.Quote(target))
		if in == nil {
			return
		}
		expectAdmittedInput(t, r, in)
	})
}

// admittedByGate runs r through the gate and returns what it admitted; nil when it refused r,
// which must then be a registered answer below 500 (what names r in the failure).
func admittedByGate(t *testing.T, r *http.Request, what string) *Input {
	t.Helper()
	var in *Input
	rec := httptest.NewRecorder()
	Gate(func(w http.ResponseWriter, r *http.Request) { in, _ = InputOf(r) })(rec, r)
	if in == nil {
		if _, ok := testutil.RegisteredAnswer(rec); !ok || rec.Code >= http.StatusInternalServerError {
			t.Fatalf("%s refused with the unregistered answer %d %q", what, rec.Code, rec.Body.String())
		}
	}
	return in
}

// expectAdmittedInput checks everything the gate promises about what it let through.
func expectAdmittedInput(t *testing.T, r *http.Request, in *Input) {
	t.Helper()
	endpoint, params, ok := match(r.URL.Path)
	if !ok || r.URL.EscapedPath() != r.URL.Path || endpoint.opFor(r.Method) != in.Op || params != in.params {
		t.Fatalf("%s %q admitted as the wrong operation", r.Method, r.URL.String())
	}
	for name, v := range in.query {
		if param := in.Op.queryParam(name); param == nil || !param.Int.Accepts(v) || len(in.query) > in.Op.MaxQuery {
			t.Fatalf("%q: query %s=%d admitted", r.URL.String(), name, v)
		}
	}
	for _, param := range in.Op.Query {
		if _, present := in.query[param.Name]; param.Required && !present {
			t.Fatalf("%q: admitted without the required %s", r.URL.String(), param.Name)
		}
	}
	if in.Op.Body == nil {
		if len(in.body) != 0 {
			t.Fatalf("%s %q: a body reached a bodiless operation", r.Method, r.URL.Path)
		}
		return
	}
	if len(in.body) > bodyLimit(in.Op.Body) {
		t.Fatalf("%s %q: a %d-byte body passed the %d-byte bound", r.Method, r.URL.Path, len(in.body), bodyLimit(in.Op.Body))
	}
	if _, ok := checkBody(in.body, in.Op.Body); !ok {
		t.Fatalf("%s %q: admitted %q, which the table refuses", r.Method, r.URL.Path, in.body)
	}
	if len(in.body) == 0 {
		return
	}
	dec := json.NewDecoder(bytes.NewReader(in.body))
	dec.UseNumber()
	var decoded any
	if err := dec.Decode(&decoded); err != nil {
		t.Fatalf("%s %q: admitted %q, which is not JSON: %v", r.Method, r.URL.Path, in.body, err)
	}
	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if _, ok := checkBody(reencoded, in.Op.Body); !ok {
		t.Fatalf("%s %q: %q admitted but its re-encoding %q refused", r.Method, r.URL.Path, in.body, reencoded)
	}
}
