package contract

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

// The contract is proved by walking it: every operation's canonical request is admitted, and
// every derived mutation is refused with exactly the answer the table registers for it. The
// values are real: random bytes from the CSPRNG in the declared sizes and structures.

const (
	exampleConversation = "3b241101-e2bb-4255-8caf-4136c566a962"
	exampleNote         = "8e7d6c5b-4a39-4281-9f0e-0d1c2b3a4958"
	exampleSolution     = "48213"
	exampleSeq          = 1
	exampleTTL          = 300
	exampleDifficulty   = 18
	examplePendingToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwZW5kaW5nIn0.c2lnbmF0dXJlLWJ5dGVz"
	jsonContentType     = "application/json"
)

func randomBytes(t testing.TB, n int) []byte {
	t.Helper()
	raw, err := cryptoengine.RandomBytes(n)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return raw
}

// roomBlob builds a structurally valid room message or note: header with the given magic and
// one wrap, then the smallest padded frame and its tag.
func roomBlob(t testing.TB, magic string, wraps int) string {
	t.Helper()
	const smallestFrame = 256
	raw := randomBytes(t, utils.RoomHeaderBytes+wraps*utils.RoomWrapBytes+smallestFrame+cryptoengine.GCMTagSize)
	copy(raw, magic)
	raw[len(magic)] = utils.RoomVersion
	raw[utils.RoomHeaderBytes-1] = byte(wraps)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// exampleString is the canonical valid value of a pattern.
func exampleString(t testing.TB, p *Pattern) string {
	t.Helper()
	switch p {
	case patternUUIDv4:
		return uuid.NewString()
	case patternKey32, patternInviteToken, patternRoomCard, patternRoomVault, patternRoomRole:
		return base64.RawURLEncoding.EncodeToString(randomBytes(t, base64.RawURLEncoding.DecodedLen(p.MaxLen)))
	case patternChallenge, patternSalt:
		return hex.EncodeToString(randomBytes(t, p.MaxLen/2))
	case patternSolution:
		return exampleSolution
	case patternPendingToken:
		return examplePendingToken
	case patternMessage:
		return base64.RawURLEncoding.EncodeToString(randomBytes(t, utils.MinCiphertextBytes))
	case patternNote:
		return roomBlob(t, utils.RoomNoteMagic, noteWraps)
	}
	t.Fatalf("no example for pattern %s", p.Name)
	return ""
}

// exampleInt is the canonical valid value of a range.
func exampleInt(t testing.TB, r *IntRange) int64 {
	t.Helper()
	switch r {
	case rangeSeq:
		return exampleSeq
	case rangeAfter:
		return 0
	case rangeMaxMembers:
		return config.MinRoomMembers
	case rangeExpiry:
		return (time.Now().Unix()/secondsPerHour + 2) * secondsPerHour
	case rangeUnixTime:
		return time.Now().Unix()
	case rangeTTL:
		return exampleTTL
	case rangeDifficulty:
		return exampleDifficulty
	}
	t.Fatalf("no example for range %s", r.Name)
	return 0
}

// mutation replaces (raw != "") or drops (drop) the value at a dotted field path.
type mutation struct {
	path string
	raw  string
	drop bool
}

// buildBody writes the canonical body compactly, in table order, with one mutation applied.
func buildBody(t testing.TB, fields []Field, prefix string, m mutation) string {
	t.Helper()
	members := make([]string, 0, len(fields))
	for i := range fields {
		f := &fields[i]
		path := prefix + f.Name
		if m.path == path && m.drop {
			continue
		}
		value := exampleValue(t, f, path, m)
		if m.path == path && m.raw != "" {
			value = m.raw
		}
		members = append(members, strconv.Quote(f.Name)+":"+value)
	}
	return "{" + strings.Join(members, ",") + "}"
}

func exampleValue(t testing.TB, f *Field, path string, m mutation) string {
	t.Helper()
	switch f.Kind {
	case KindString:
		return strconv.Quote(exampleString(t, f.Str))
	case KindInt:
		return strconv.FormatInt(exampleInt(t, f.Int), 10)
	case KindBool:
		return "false"
	default:
		return buildBody(t, f.Fields, path+".", m)
	}
}

// requestFor builds the canonical request of op on e, with the given body and query.
func requestFor(e *Endpoint, op *Op, body, query string) *http.Request {
	path := strings.NewReplacer(paramConversation, exampleConversation, paramNote, exampleNote).Replace(e.Template)
	if query != "" {
		path += "?" + query
	}
	r := httptest.NewRequest(op.Method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set(utils.HeaderContentType, jsonContentType)
	}
	return r
}

// serve runs r through the gate and reports whether the handler ran.
func serve(r *http.Request) (*httptest.ResponseRecorder, bool) {
	reached := false
	rec := httptest.NewRecorder()
	Gate(func(w http.ResponseWriter, r *http.Request) {
		_, reached = InputOf(r)
	})(rec, r)
	return rec, reached
}

// expectRefused asserts the gate answered exactly what apperr registers for code.
func expectRefused(t *testing.T, r *http.Request, code apperr.Code, what string) {
	t.Helper()
	got, reached := serve(r)
	want := httptest.NewRecorder()
	apperr.Write(want, "test", code)
	if reached || got.Code != want.Code || got.Body.String() != want.Body.String() ||
		got.Header().Get(utils.HeaderContentType) != want.Header().Get(utils.HeaderContentType) {
		id, _ := apperr.Describe(code)
		t.Errorf("%s: reached=%v answer %d %q, want %s (%d %q)", what, reached, got.Code, got.Body.String(), id, want.Code, want.Body.String())
	}
}

func expectAdmitted(t *testing.T, r *http.Request, what string) {
	t.Helper()
	if rec, reached := serve(r); !reached {
		t.Errorf("%s: refused with %d %q", what, rec.Code, rec.Body.String())
	}
}

// forEachOp runs fn on every operation of the table.
func forEachOp(fn func(e *Endpoint, op *Op)) {
	for i := range endpoints {
		for j := range endpoints[i].Ops {
			fn(&endpoints[i], &endpoints[i].Ops[j])
		}
	}
}

func canonicalBody(t *testing.T, op *Op) string {
	if op.Body == nil {
		return ""
	}
	return buildBody(t, op.Body.Fields, "", mutation{})
}

func TestCanonicalRequestsAdmitted(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		expectAdmitted(t, requestFor(e, op, canonicalBody(t, op), ""), op.Method+" "+e.Template)
	})
}

// TestBodiesBindToTheirModels: every canonical body decodes into the models type its handler
// binds, with no unknown field, so the table and the types cannot drift apart.
func TestBodiesBindToTheirModels(t *testing.T) {
	types := map[OpID]func() any{
		OpRegister:     func() any { return &models.RegisterRequest{} },
		OpLogin:        func() any { return &models.LoginRequest{} },
		OpMeDelete:     func() any { return &models.DeleteAccountRequest{} },
		OpInviteCreate: func() any { return &models.CreateInviteRequest{} },
		OpInviteRedeem: func() any { return &models.RedeemInviteRequest{} },
		OpRoomCreate:   func() any { return &models.CreateRoomRequest{} },
		OpRoomJoin:     func() any { return &models.JoinRoomRequest{} },
		OpMessageSend:  func() any { return &models.SendMessageRequest{} },
		OpReadMark:     func() any { return &models.MarkReadRequest{} },
		OpNoteSend:     func() any { return &models.SendNoteRequest{} },
		OpMemberRole:   func() any { return &models.SetRoleRequest{} },
	}
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body == nil {
			return
		}
		newType, ok := types[op.ID]
		if !ok {
			t.Fatalf("%s %s: no models type", op.Method, e.Template)
		}
		dec := json.NewDecoder(strings.NewReader(canonicalBody(t, op)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(newType()); err != nil {
			t.Errorf("%s %s: %v", op.Method, e.Template, err)
		}
	})
}

// fieldMutations derives, for one field, every mutation the table must refuse and its answer.
func fieldMutations(t *testing.T, body *Body, f *Field, path string) map[string]struct {
	m    mutation
	code apperr.Code
} {
	out := map[string]struct {
		m    mutation
		code apperr.Code
	}{}
	add := func(name string, m mutation, code apperr.Code) {
		out[path+": "+name] = struct {
			m    mutation
			code apperr.Code
		}{m, code}
	}
	if f.Required {
		add("missing", mutation{path: path, drop: true}, orInvalidRequest(f.Missing))
		add("null", mutation{path: path, raw: "null"}, orInvalidRequest(f.Missing))
	}
	switch f.Kind {
	case KindString:
		add("wrong type", mutation{path: path, raw: "7"}, body.Refuse)
		stringMutations(t, f, path, add)
	case KindInt:
		add("wrong type", mutation{path: path, raw: `"1"`}, body.Refuse)
		add("fraction", mutation{path: path, raw: "1.5"}, body.Refuse)
		add("below minimum", mutation{path: path, raw: strconv.FormatInt(f.Int.Min-1, 10)}, orInvalidRequest(f.Invalid))
		if f.Int.Max < math.MaxInt64 {
			add("above maximum", mutation{path: path, raw: strconv.FormatInt(f.Int.Max+1, 10)}, orInvalidRequest(f.Invalid))
		}
	case KindBool:
		add("wrong type", mutation{path: path, raw: `"true"`}, body.Refuse)
	case KindObject:
		add("wrong type", mutation{path: path, raw: `"x"`}, body.Refuse)
		add("array", mutation{path: path, raw: "[]"}, body.Refuse)
	}
	return out
}

// stringMutations: one character too long and too short, uppercase where lowercase is
// required, and a non-canonical base64url tail.
func stringMutations(t *testing.T, f *Field, path string, add func(string, mutation, apperr.Code)) {
	valid := exampleString(t, f.Str)
	invalid := orInvalidRequest(f.Invalid)
	if f.Str.MaxLen == f.Str.MinLen {
		add("one char too long", mutation{path: path, raw: strconv.Quote(valid + "A")}, invalid)
		add("one char too short", mutation{path: path, raw: strconv.Quote(valid[:len(valid)-1])}, invalid)
	}
	if f.Str.MinLen > 0 {
		add("empty", mutation{path: path, raw: `""`}, invalid)
	}
	if upper := strings.ToUpper(valid); upper != valid && (f.Str == patternUUIDv4 || f.Str == patternChallenge || f.Str == patternSalt) {
		add("uppercase", mutation{path: path, raw: strconv.Quote(upper)}, invalid)
	}
	if size := base64.RawURLEncoding.DecodedLen(f.Str.MaxLen); f.Str.MinLen == f.Str.MaxLen && size%base64BytesPerGroup != 0 &&
		f.Str != patternUUIDv4 && f.Str != patternChallenge && f.Str != patternSalt {
		// 'B' is index 1: its low bits are never zero, so it is never a canonical last char
		add("non-canonical tail", mutation{path: path, raw: strconv.Quote(valid[:len(valid)-1] + "B")}, invalid)
	}
	add("padded", mutation{path: path, raw: strconv.Quote(valid + "=")}, invalid)
}

func TestFieldMutationsRefused(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body == nil {
			return
		}
		var walkFields func(fields []Field, prefix string)
		walkFields = func(fields []Field, prefix string) {
			for i := range fields {
				f := &fields[i]
				for name, c := range fieldMutations(t, op.Body, f, prefix+f.Name) {
					body := buildBody(t, op.Body.Fields, "", c.m)
					expectRefused(t, requestFor(e, op, body, ""), c.code, op.Method+" "+e.Template+" "+name)
				}
				if f.Kind == KindObject {
					walkFields(f.Fields, prefix+f.Name+".")
				}
			}
		}
		walkFields(op.Body.Fields, "")
	})
}

// TestBodyShapeRefused: extra key, duplicate key, trailing data, a second value, not an
// object, wrong content type, oversized by one byte; the exact bound is still admitted.
func TestBodyShapeRefused(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body == nil {
			return
		}
		name := op.Method + " " + e.Template
		valid := canonicalBody(t, op)
		first := op.Body.Fields[0]
		duplicate := valid[:len(valid)-1] + "," + strconv.Quote(first.Name) + ":" + exampleValue(t, &first, first.Name, mutation{}) + "}"
		for what, body := range map[string]string{
			"extra key":          valid[:len(valid)-1] + `,"extra":1}`,
			"duplicate key":      duplicate,
			"trailing data":      valid + "x",
			"second value":       valid + "{}",
			"array":              "[" + valid + "]",
			"not JSON":           valid[:len(valid)-1],
			"case-folded key":    strings.Replace(valid, strconv.Quote(first.Name), strconv.Quote(strings.ToUpper(first.Name)), 1),
			"oversized by one":   valid + strings.Repeat(" ", MaxBodyBytes(op.Body)+1-len(valid)),
			"undeclared nesting": valid[:len(valid)-1] + `,"extra":{"a":{"b":1}}}`,
		} {
			expectRefused(t, requestFor(e, op, body, ""), op.Body.Refuse, name+" "+what)
		}
		expectAdmitted(t, requestFor(e, op, valid+strings.Repeat(" ", MaxBodyBytes(op.Body)-len(valid)), ""), name+" at the bound")
		for _, contentType := range []string{"text/plain", "application/json; charset=utf-8", "Application/JSON", ""} {
			r := requestFor(e, op, valid, "")
			r.Header.Set(utils.HeaderContentType, contentType)
			expectRefused(t, r, apperr.UnsupportedMediaType, name+" content type "+strconv.Quote(contentType))
		}
		r := requestFor(e, op, valid, "")
		r.Header.Add(utils.HeaderContentType, jsonContentType)
		expectRefused(t, r, apperr.UnsupportedMediaType, name+" two content types")
	})
}

// TestBodilessOperationsRefuseBodies: a body sent where none is taken.
func TestBodilessOperationsRefuseBodies(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body != nil {
			return
		}
		name := op.Method + " " + e.Template
		expectRefused(t, requestFor(e, op, "{}", ""), apperr.InvalidRequest, name+" JSON body")
		r := requestFor(e, op, "x", "")
		r.Header.Set(utils.HeaderContentType, "text/plain")
		expectRefused(t, r, apperr.UnsupportedMediaType, name+" text body")
	})
}

// TestEmptyBodies: a POST that needs a body and has none declares no type (415); an empty
// DELETE body is missing (400); registration phase 1 takes an empty body as {} (412: no PoW).
func TestEmptyBodies(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body == nil {
			return
		}
		r := requestFor(e, op, "", "")
		switch {
		case op.Body.Optional:
			expectRefused(t, r, apperr.PoWRequired, op.Method+" "+e.Template+" empty")
		case op.Method == http.MethodPost:
			expectRefused(t, r, apperr.UnsupportedMediaType, op.Method+" "+e.Template+" empty")
		default:
			expectRefused(t, r, op.Body.Refuse, op.Method+" "+e.Template+" empty")
		}
	})
}

func TestQueries(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		body := canonicalBody(t, op)
		name := op.Method + " " + e.Template
		refused := []string{"x=1", "x", "&", "after=1&after=1", "after=1&before=2", "after=1&", "after=%31", "After=1",
			"after=", "after=-1", "after=01", "after=1e3", "after=+1", "after=99999999999999999999", "after=9223372036854775808"}
		if len(op.Query) == 0 {
			refused = append(refused, "after=1", "before=1")
		} else {
			refused = append(refused, "before=0", "before=-1", "before=0x10")
			for _, q := range []string{"after=0", "after=42", "before=1", "before=9223372036854775807"} {
				expectAdmitted(t, requestFor(e, op, body, q), name+" ?"+q)
			}
		}
		for _, q := range refused {
			expectRefused(t, requestFor(e, op, body, q), apperr.InvalidRequest, name+" ?"+q)
		}
	})
}

func TestMethods(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, "TRACE"}
	for i := range endpoints {
		e := &endpoints[i]
		for _, method := range methods {
			if e.opFor(method) != nil {
				continue
			}
			r := httptest.NewRequest(method, strings.NewReplacer(paramConversation, exampleConversation, paramNote, exampleNote).Replace(e.Template), nil)
			want := apperr.MethodNotAllowed
			if method == http.MethodHead && e.BareHead {
				want = apperr.HeadNotAllowed
			}
			expectRefused(t, r, want, method+" "+e.Template)
		}
	}
}

func TestPaths(t *testing.T) {
	const conversations = "/api/v2/conversations/"
	for _, path := range []string{
		conversations,
		conversations + exampleConversation + "/",
		conversations + exampleConversation + "/messages/x",
		conversations + exampleConversation + "/messages/" + exampleNote,
		conversations + exampleConversation + "/members/" + exampleNote,
		conversations + exampleConversation + "/notes/",
		conversations + exampleConversation + "/notes/x",
		conversations + exampleConversation + "/notes/" + exampleNote + "/x",
		conversations + exampleConversation + "/roster",
		conversations + strings.ToUpper(exampleConversation),
		conversations + "3b241101-e2bb-1255-8caf-4136c566a962", // version 1
		conversations + "3b241101-e2bb-4255-cfaf-4136c566a962", // variant 110
		conversations + "{" + exampleConversation + "}",
		conversations + "%33b241101-e2bb-4255-8caf-4136c566a962", // percent-encoded '3'
		"/api/v2/unknown",
		"/api/v2/me/",
	} {
		expectRefused(t, httptest.NewRequest(http.MethodGet, path, nil), apperr.RouteNotFound, path)
	}
}

// TestPathIDsParsed: the handler receives the parsed conversation and note ids.
func TestPathIDsParsed(t *testing.T) {
	r := httptest.NewRequest(http.MethodDelete, "/api/v2/conversations/"+exampleConversation+"/notes/"+exampleNote, nil)
	var got *Input
	Gate(func(w http.ResponseWriter, r *http.Request) { got, _ = InputOf(r) })(httptest.NewRecorder(), r)
	if got == nil || got.Op.ID != OpNoteDelete || got.PathID(PathConversation).String() != exampleConversation ||
		got.PathID(PathNote).String() != exampleNote {
		t.Fatalf("admitted %+v", got)
	}
}

// TestBodyBoundsBelowGlobalCap: every operation's own bound fits under MAX_REQUEST_BODY_BYTES.
func TestBodyBoundsBelowGlobalCap(t *testing.T) {
	forEachOp(func(e *Endpoint, op *Op) {
		if op.Body != nil && MaxBodyBytes(op.Body) > config.GetMaxRequestBodyBytes() {
			t.Errorf("%s %s: bound %d above the global cap", op.Method, e.Template, MaxBodyBytes(op.Body))
		}
	})
}

// TestDocMatchesTable: the committed document is exactly what the table renders.
func TestDocMatchesTable(t *testing.T) {
	committed, err := os.ReadFile(DocPath)
	if err != nil {
		t.Fatalf("read %s: %v", DocPath, err)
	}
	if string(committed) != Render() {
		t.Fatalf("%s is stale: run go generate ./internal/contract", DocPath)
	}
}
