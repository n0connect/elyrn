package apperr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/encryption"
	"elyrn/internal/models"
	"elyrn/internal/pow"
	"elyrn/internal/store"
	"elyrn/internal/utils"
)

var idPattern = regexp.MustCompile(`^E_[A-Z0-9_]+$`)

// TestRegistryComplete: every constant from MethodNotAllowed to Internal is registered, and no
// registry key lies outside that range (a code added to the const block must be registered).
func TestRegistryComplete(t *testing.T) {
	for code := MethodNotAllowed; code <= Internal; code++ {
		if _, ok := registry[code]; !ok {
			t.Errorf("code %d has no registry entry", int(code))
		}
	}
	if want := int(Internal - MethodNotAllowed + 1); len(registry) != want {
		t.Errorf("registry has %d entries, want %d", len(registry), want)
	}
}

func TestRegistryEntriesWellFormed(t *testing.T) {
	seen := map[string]Code{}
	for code, e := range registry {
		if !idPattern.MatchString(e.id) {
			t.Errorf("code %d: id %q does not match %s", int(code), e.id, idPattern)
		}
		if other, dup := seen[e.id]; dup {
			t.Errorf("id %q used by codes %d and %d", e.id, int(other), int(code))
		}
		seen[e.id] = code
		if e.status < 400 || e.status > 599 {
			t.Errorf("%s: status %d outside 400..599", e.id, e.status)
		}
		if e.body == "" {
			t.Errorf("%s: empty public sentence", e.id)
		}
		if _, ok := knownLevels[e.level]; !ok {
			t.Errorf("%s: unknown log level %q", e.id, e.level)
		}
		if e.shape != shapeText && e.shape != shapeJSON && e.shape != shapeEmpty {
			t.Errorf("%s: unknown wire shape %d", e.id, int(e.shape))
		}
	}
}

var knownLevels = map[utils.LogLevel]struct{}{
	utils.LogLevelDEBUG: {}, utils.LogLevelINFO: {}, utils.LogLevelWARN: {}, utils.LogLevelERROR: {},
}

// jsonWire pins login's failure answers to the exact (status, body) LoginHandler wrote before
// they moved into the registry, a send's "id taken" 409, and the role answer that shares a status
// with another answer of its route (in JSON so the browser can read them);
// frontend/js/errors.js fromApi maps these messages.
var jsonWire = map[Code]struct {
	status int
	body   string
}{
	LoginBodyInvalid:   {400, `{"success":false,"message":"Invalid request"}`},
	LoginKeyMalformed:  {401, `{"success":false,"message":"Invalid credentials"}`},
	LoginLookupFailed:  {500, `{"success":false,"message":"Internal server error"}`},
	LoginNoAccount:     {401, `{"success":false,"message":"Invalid credentials"}`},
	LoginLegacyAccount: {401, `{"success":false,"message":"Invalid credentials"}`},
	IDTaken:            {409, `{"success":false,"message":"Id taken"}`},
	RoleNotAllowed:     {403, `{"success":false,"message":"Role not allowed"}`},
}

// emptyWire pins the answers with a status line only: HEAD on register, login and the PoW
// challenge answered a bare 405 (w.WriteHeader) before the input contract's gate took it over.
// The healthcheck's 503 is a status line only too: no detail leaves the server.
var emptyWire = map[Code]int{HeadNotAllowed: http.StatusMethodNotAllowed, HealthUnavailable: http.StatusServiceUnavailable}

// TestWireAnswers pins every code to the exact (status, body) the server answered before the
// registry existed; clients compare these bytes.
func TestWireAnswers(t *testing.T) {
	want := map[Code]struct {
		status int
		body   string
	}{
		MethodNotAllowed:      {405, "Method not allowed"},
		InvalidRequest:        {400, "Invalid request"},
		RouteNotFound:         {404, "Not Found"},
		UnsupportedMediaType:  {415, "Unsupported Media Type"},
		CrossOrigin:           {403, "Forbidden"},
		NoSession:             {401, "Unauthorized"},
		SessionContextMissing: {401, "Unauthorized"},
		MemberNotFound:        {401, "Unauthorized"},
		PendingTokenRequired:  {400, "Pending token required"},
		PendingTokenInvalid:   {401, "Unauthorized"},
		AccountExists:         {401, "Unauthorized"},
		PoWRequired:           {412, "Proof of work required"},
		PoWInvalid:            {403, "Invalid proof of work"},
		PoWRateLimited:        {429, "Too many requests"},
		PoWCapacity:           {503, "Service unavailable"},
		RateLimited:           {429, "Too many requests"},
		SubscriberLimit:       {429, "Too many requests"},
		Argon2Busy:            {503, "Service unavailable"},
		PendingStoreFull:      {503, "Service unavailable"},
		StoreUnavailable:      {503, "Service unavailable"},
		ShuttingDown:          {503, "Service unavailable"},
		RequestCancelled:      {503, "Service unavailable"},
		InvalidInput:          {400, "Invalid request"},
		NotFound:              {404, "Not found"},
		LimitReached:          {429, "Too many requests"},
		Conflict:              {409, "Conflict"},
		RoomFull:              {409, "Room full"},
		RosterChanged:         {412, "Roster changed"},
		IdentityUnset:         {403, "Forbidden"},
		Forbidden:             {403, "Forbidden"},
		AccountCollision:      {500, "Internal server error"},
		InputUnchecked:        {500, "Internal server error"},
		Panic:                 {500, "Internal server error"},
		Internal:              {500, "Internal server error"},
	}
	if len(want)+len(jsonWire)+len(emptyWire) != len(registry) {
		t.Fatalf("pinned %d answers, registry has %d", len(want)+len(jsonWire)+len(emptyWire), len(registry))
	}
	for code, status := range emptyWire {
		rec := httptest.NewRecorder()
		Write(rec, "test", code)
		if rec.Code != status || rec.Body.Len() != 0 || rec.Header().Get("Content-Type") != "" {
			t.Errorf("code %d: got %d %q %v, want a bare %d", int(code), rec.Code, rec.Body.String(), rec.Header(), status)
		}
	}
	for code, w := range want {
		rec := httptest.NewRecorder()
		Write(rec, "test", code)
		assertAnswer(t, rec, w.status, w.body)
	}
	for code, w := range jsonWire {
		rec := httptest.NewRecorder()
		Write(rec, "test", code)
		assertAnswer(t, rec, w.status, w.body)
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("code %d: Content-Type %q, want application/json", int(code), ct)
		}
	}
}

// TestShapes: exactly the pinned JSON codes answer in JSON; everything else stays text.
func TestShapes(t *testing.T) {
	for code, e := range registry {
		_, isJSON := jsonWire[code]
		if isJSON != (e.shape == shapeJSON) {
			t.Errorf("%s: shape %d, pinned as JSON: %v", e.id, int(e.shape), isJSON)
		}
	}
}

// TestWriteMatchesHTTPError: a text code's bytes and headers are exactly those of http.Error.
func TestWriteMatchesHTTPError(t *testing.T) {
	for code, e := range registry {
		if e.shape != shapeText {
			continue
		}
		got, ref := httptest.NewRecorder(), httptest.NewRecorder()
		Write(got, "test", code)
		http.Error(ref, e.body, e.status)
		if got.Code != ref.Code || got.Body.String() != ref.Body.String() {
			t.Errorf("%s: got %d %q, want %d %q", e.id, got.Code, got.Body.String(), ref.Code, ref.Body.String())
		}
		for _, h := range []string{"Content-Type", "X-Content-Type-Options"} {
			if got.Header().Get(h) != ref.Header().Get(h) {
				t.Errorf("%s: header %s = %q, want %q", e.id, h, got.Header().Get(h), ref.Header().Get(h))
			}
		}
		if len(got.Header()) != len(ref.Header()) {
			t.Errorf("%s: %d headers, want %d", e.id, len(got.Header()), len(ref.Header()))
		}
	}
}

// TestWriteMatchesLoginEncoding: a JSON code's bytes and headers are exactly those of the
// encoder and type LoginHandler used before (and still uses for its success answer).
func TestWriteMatchesLoginEncoding(t *testing.T) {
	for code, e := range registry {
		if e.shape != shapeJSON {
			continue
		}
		got, ref := httptest.NewRecorder(), httptest.NewRecorder()
		Write(got, "test", code)
		utils.EncodeJSONResponse(ref, models.LoginResponse{Success: false, Message: e.body}, e.status)
		if got.Code != ref.Code || got.Body.String() != ref.Body.String() {
			t.Errorf("%s: got %d %q, want %d %q", e.id, got.Code, got.Body.String(), ref.Code, ref.Body.String())
		}
		if len(got.Header()) != len(ref.Header()) || got.Header().Get("Content-Type") != ref.Header().Get("Content-Type") {
			t.Errorf("%s: headers %v, want %v", e.id, got.Header(), ref.Header())
		}
	}
}

// TestWriteCauseKeepsTheCauseOffTheWire: the cause is logged, the wire carries the code's answer.
func TestWriteCauseKeepsTheCauseOffTheWire(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteCause(rec, "test", LoginLookupFailed, errors.New("pepper missing"))
	assertAnswer(t, rec, 500, `{"success":false,"message":"Internal server error"}`)
}

func TestUnregisteredCodeAnswersInternal(t *testing.T) {
	rec := httptest.NewRecorder()
	Write(rec, "test", Code(0))
	assertAnswer(t, rec, 500, "Internal server error")
}

// TestSentinelsMapped: every sentinel a handler answers maps to its code, also when wrapped.
func TestSentinelsMapped(t *testing.T) {
	want := map[error]Code{
		chat.ErrInvalidInput:     InvalidInput,
		chat.ErrNotFound:         NotFound,
		chat.ErrLimitReached:     LimitReached,
		chat.ErrConflict:         Conflict,
		chat.ErrIDTaken:          IDTaken,
		chat.ErrRoomFull:         RoomFull,
		chat.ErrStale:            RosterChanged,
		chat.ErrIdentityUnset:    IdentityUnset,
		chat.ErrForbidden:        Forbidden,
		chat.ErrRoleNotAllowed:   RoleNotAllowed,
		auth.ErrBusy:             Argon2Busy,
		auth.ErrPendingStoreFull: PendingStoreFull,
		pow.ErrRateLimited:       PoWRateLimited,
		pow.ErrCapacity:          PoWCapacity,
		pow.ErrInvalidSolution:   PoWInvalid,
		store.ErrUnavailable:     StoreUnavailable,
		encryption.ErrClosing:    ShuttingDown,
		context.Canceled:         RequestCancelled,
	}
	if len(want) != len(sentinels) {
		t.Errorf("pinned %d sentinels, table has %d", len(want), len(sentinels))
	}
	for err, code := range want {
		for _, e := range []error{err, fmt.Errorf("op: %w", err)} {
			got, ok := CodeOf(e)
			if !ok || got != code {
				t.Errorf("CodeOf(%v) = %d, %v; want %d", e, int(got), ok, int(code))
			}
		}
	}
}

func TestUnknownErrorAnswersInternal(t *testing.T) {
	if _, ok := CodeOf(errors.New("disk on fire")); ok {
		t.Fatal("an unknown error must not map to a code")
	}
	rec := httptest.NewRecorder()
	WriteError(rec, "test", errors.New("disk on fire"))
	assertAnswer(t, rec, 500, "Internal server error")
	if rec.Body.String() != "Internal server error\n" {
		t.Fatalf("the cause leaked to the wire: %q", rec.Body.String())
	}
}

func TestWriteErrorUsesSentinelCode(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteError(rec, "test", fmt.Errorf("join: %w", chat.ErrRoomFull))
	assertAnswer(t, rec, 409, "Room full")
}

func assertAnswer(t *testing.T, rec *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if rec.Code != status || rec.Body.String() != body+"\n" {
		t.Errorf("got %d %q, want %d %q", rec.Code, rec.Body.String(), status, body+"\n")
	}
}

// TestOperatorCodesWellFormed: the operator codes (package opcode) follow the id pattern, carry a
// sentence, and share no id with each other or with the request registry.
func TestOperatorCodesWellFormed(t *testing.T) {
	seen := map[string]struct{}{}
	for _, e := range registry {
		seen[e.id] = struct{}{}
	}
	for _, c := range opcode.All {
		if !idPattern.MatchString(c.ID) {
			t.Errorf("operator code id %q does not match %s", c.ID, idPattern)
		}
		if c.Sentence == "" {
			t.Errorf("%s: empty operator sentence", c.ID)
		}
		if _, dup := seen[c.ID]; dup {
			t.Errorf("id %q is registered twice", c.ID)
		}
		seen[c.ID] = struct{}{}
	}
}

// nginxSite is nginx's site configuration (it holds the /api/ error answers), from here
const nginxSite = "../../../nginx-site.conf"

// TestEdgeAnswers: nginx's own /api/ answers are registered once, with ids no other code uses,
// in apperr's JSON shape plus the code; and nginx-site.conf returns exactly these bytes.
func TestEdgeAnswers(t *testing.T) {
	seen := map[string]struct{}{}
	for _, e := range registry {
		seen[e.id] = struct{}{}
	}
	for _, c := range opcode.All {
		seen[c.ID] = struct{}{}
	}
	for _, a := range EdgeAnswers {
		if !idPattern.MatchString(a.ID) {
			t.Errorf("edge id %q does not match %s", a.ID, idPattern)
		}
		if _, dup := seen[a.ID]; dup {
			t.Errorf("edge id %q is registered twice", a.ID)
		}
		seen[a.ID] = struct{}{}
		var body struct {
			Success *bool  `json:"success"`
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		if err := json.Unmarshal([]byte(a.Body()), &body); err != nil || body.Success == nil || *body.Success ||
			body.Message != a.Sentence || body.Code != a.ID || a.Status < 400 || a.Status > 599 {
			t.Errorf("%s: malformed edge answer %d %s", a.ID, a.Status, a.Body())
		}
	}
	site, err := os.ReadFile(nginxSite)
	if os.IsNotExist(err) {
		// The test container carries backend/ only; make check-hardening compares the same bytes
		t.Skip("nginx-site.conf is outside this tree")
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range EdgeAnswers {
		if want := fmt.Sprintf("return %d '%s';", a.Status, a.Body()); !strings.Contains(string(site), want) {
			t.Errorf("nginx-site.conf does not return %s", want)
		}
	}
}
