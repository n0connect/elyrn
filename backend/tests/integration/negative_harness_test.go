package integration

// The shared harness of the negative-use tests (negative_*_test.go): what a confused, careless or
// hostile client does with a correct-looking API. Every case asserts the exact registered answer
// (testutil.IsAnswer: status, body and content type, byte for byte) and re-reads the state
// afterwards, so a refusal that still changed something fails. The generic classes iterate the
// input contract's route table (contract.Endpoints), so an endpoint added later is covered, or
// fails here until it is given a shaped body.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/contract"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"

	"github.com/google/uuid"
)

// The path parameters of the table's templates (contract: "{id}" the conversation, "{note}" the
// note); a template left with a brace after substitution names a parameter this harness does
// not know, and fails loudly.
const (
	templateConversation = "{id}"
	templateNote         = "{note}"
	templateBrace        = "{"
	// unsolvedNonce answers a real challenge with a nonce that (almost surely) does not meet its
	// difficulty: the body passes the gate's shape check and never reaches a valid proof
	unsolvedNonce = "0"
	// bearerPrefix is how a confused client would send the session token as a header
	bearerPrefix = "Bearer "
	// headerAuthorization is the header a token-in-header client uses
	headerAuthorization = "Authorization"
)

// publicOps are the operations served without a session; every other operation of the table
// must refuse every non-session (negative_auth_test.go), so a new operation is protected by
// default in these tests.
var publicOps = map[contract.OpID]bool{
	contract.OpPoWChallenge: true,
	contract.OpRegister:     true,
	contract.OpLogin:        true,
	contract.OpLogout:       true,
	contract.OpHealth:       true,
}

// cursorValues are valid values of each page cursor the table accepts (the lowest each admits)
var cursorValues = map[string]string{
	models.QueryAfter:  "0",
	models.QueryBefore: "1",
}

// route is one operation of the table, optionally with one of its query parameters.
type route struct {
	op       contract.Op
	template string
	query    string
}

func (r route) label() string {
	label := r.op.Method + " " + r.template
	if r.query != "" {
		label += "?" + r.query
	}
	return label
}

// conversationScoped reports whether the route addresses one conversation.
func (r route) conversationScoped() bool {
	return strings.Contains(r.template, templateConversation)
}

// path fills the template with conv and note and appends the query.
func (r route) path(t *testing.T, conv, note uuid.UUID) string {
	t.Helper()
	path := strings.ReplaceAll(r.template, templateConversation, conv.String())
	path = strings.ReplaceAll(path, templateNote, note.String())
	if strings.Contains(path, templateBrace) {
		t.Fatalf("%s: the template has a parameter this harness does not know", r.label())
	}
	if r.query != "" {
		path += "?" + r.query
	}
	return path
}

// tableRoutes is every operation of the input contract's table, once bare and once per accepted
// query parameter (each alone, at a valid value).
func tableRoutes(t *testing.T) []route {
	t.Helper()
	var routes []route
	for _, endpoint := range contract.Endpoints() {
		for _, op := range endpoint.Ops {
			routes = append(routes, route{op: op, template: endpoint.Template})
			for _, q := range op.Query {
				value, ok := cursorValues[q.Name]
				if !ok {
					t.Fatalf("%s %s: query parameter %q has no valid value in this harness", op.Method, endpoint.Template, q.Name)
				}
				routes = append(routes, route{op: op, template: endpoint.Template, query: q.Name + "=" + value})
			}
		}
	}
	if len(routes) == 0 {
		t.Fatal("the contract table is empty")
	}
	return routes
}

// protectedRoutes is every route of the table that needs a session.
func protectedRoutes(t *testing.T) []route {
	t.Helper()
	var out []route
	for _, r := range tableRoutes(t) {
		if !publicOps[r.op.ID] {
			out = append(out, r)
		}
	}
	return out
}

// conversationRoutes is every route of the table that addresses one conversation.
func conversationRoutes(t *testing.T) []route {
	t.Helper()
	var out []route
	for _, r := range tableRoutes(t) {
		if r.conversationScoped() {
			out = append(out, r)
		}
	}
	return out
}

// shapedPoW is a proof of work the gate admits (a real, issued challenge from a client address
// of its own) that the handler refuses (the nonce is not solved).
func shapedPoW(t *testing.T, mux http.Handler) *models.PoWSolution {
	t.Helper()
	rr := newClient(t, mux).do(http.MethodGet, models.PathPoWChallenge, nil)
	expectStatus(t, rr, http.StatusOK, "pow challenge")
	var resp models.PoWChallengeResponse
	decode(t, rr, &resp)
	return resp.Challenge.Answer(unsolvedNonce)
}

// pairCiphertext is a well-formed one-to-one ciphertext (the smallest padded frame) of random
// bytes: the server cannot open it and checks its structure only.
func pairCiphertext(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, utils.MinCiphertextBytes))
}

// randomInviteToken is a token of the invite shape that no invite has.
func randomInviteToken(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, utils.InviteTokenBytes))
}

// shapedBodies is one body per operation that takes one, each admitted by the gate: built from
// owner's identity (the delete body carries owner's own auth key, so a refusal that still ran
// would erase owner). An operation whose body is missing here fails the test.
func shapedBodies(t *testing.T, mux http.Handler, owner *user) map[contract.OpID]any {
	t.Helper()
	side := sideOf(t, owner, newCode(t, 4, 24))
	create := side.createRequest(t)
	create.PoW = shapedPoW(t, mux)
	noteID, note := side.note(t, side, "noaddx:x")
	bodies := map[contract.OpID]any{
		contract.OpMeDelete:     models.DeleteAccountRequest{AuthKey: owner.authKey},
		contract.OpInviteCreate: models.CreateInviteRequest{PoW: shapedPoW(t, mux)},
		contract.OpInviteRedeem: models.RedeemInviteRequest{Token: randomInviteToken(t)},
		contract.OpRoomCreate:   create,
		contract.OpRoomJoin:     side.joinRequest(t),
		contract.OpMessageSend:  models.SendMessageRequest{ID: newMessageID(), Ciphertext: pairCiphertext(t)},
		contract.OpReadMark:     models.MarkReadRequest{Seq: 1},
		contract.OpNoteSend:     models.SendNoteRequest{ID: noteID, To: side.member.Card, Blob: note},
	}
	for _, r := range tableRoutes(t) {
		if r.op.Body == nil || publicOps[r.op.ID] {
			continue
		}
		if _, ok := bodies[r.op.ID]; !ok {
			t.Fatalf("%s: no shaped body for this operation; add one to shapedBodies", r.label())
		}
	}
	return bodies
}

// bodyFor is the shaped body of r, or nil for an operation that takes none.
func bodyFor(r route, bodies map[contract.OpID]any) any {
	if r.op.Body == nil {
		return nil
	}
	return bodies[r.op.ID]
}

// expectAnswer insists rr is exactly the registered answer of code.
func expectAnswer(t *testing.T, rr *httptest.ResponseRecorder, code apperr.Code, what string) {
	t.Helper()
	if testutil.IsAnswer(rr, code) {
		return
	}
	id, _ := apperr.Describe(code)
	got := "an unregistered answer"
	if gotCode, ok := testutil.RegisteredAnswer(rr); ok {
		got, _ = apperr.Describe(gotCode)
	}
	t.Fatalf("%s: %d %q (%s), want %s", what, rr.Code, rr.Body.String(), got, id)
}

// expectIdentical insists two answers are the same bytes: status, every header and the body.
func expectIdentical(t *testing.T, got, want *httptest.ResponseRecorder, what string) {
	t.Helper()
	if got.Code != want.Code || got.Body.String() != want.Body.String() || !reflect.DeepEqual(got.Header(), want.Header()) {
		t.Fatalf("%s: answered %d %q %v, the reference %d %q %v", what,
			got.Code, got.Body.String(), got.Header(), want.Code, want.Body.String(), want.Header())
	}
}

// negativeTables are the tables a refused request must leave as they were.
var negativeTables = []any{
	&models.User{}, &models.Invite{}, &models.Conversation{}, &models.ConversationMember{},
	&models.Message{}, &models.Room{}, &models.RoomNote{},
}

// rowCounts is the number of rows of every table in negativeTables, by table type.
type rowCounts map[string]int64

func countRows(t *testing.T) rowCounts {
	t.Helper()
	counts := rowCounts{}
	for _, model := range negativeTables {
		var n int64
		if err := database.DB.Model(model).Count(&n).Error; err != nil {
			t.Fatalf("count %T: %v", model, err)
		}
		counts[reflect.TypeOf(model).Elem().Name()] = n
	}
	return counts
}

// expectRowsUnchanged insists no table gained or lost a row since before.
func expectRowsUnchanged(t *testing.T, before rowCounts, what string) {
	t.Helper()
	if after := countRows(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("%s changed the stored rows: %v, before %v", what, after, before)
	}
}

// expectRows insists one table holds exactly want rows.
func expectRows(t *testing.T, model any, want int64, what string) {
	t.Helper()
	var n int64
	if err := database.DB.Model(model).Count(&n).Error; err != nil {
		t.Fatalf("count %T: %v", model, err)
	}
	if n != want {
		t.Fatalf("%s: %d %T rows, want %d", what, n, model, want)
	}
}

// withCookie is a client of its own address that presents value as its session cookie.
func withCookie(t *testing.T, mux http.Handler, value string) *client {
	t.Helper()
	c := newClient(t, mux)
	c.cookie = &http.Cookie{Name: auth.AuthCookieName(), Value: value}
	return c
}

// loginAgain opens a second session (another device) for u.
func loginAgain(t *testing.T, mux http.Handler, u *user) *client {
	t.Helper()
	c := newClient(t, mux)
	expectStatus(t, c.do(http.MethodPost, models.PathLogin, models.LoginRequest{AuthKey: u.authKey}), http.StatusOK, "login")
	if c.cookie == nil {
		t.Fatal("login set no session cookie")
	}
	return c
}

// registerPhase1 runs registration phase 1 from c.
func registerPhase1(t *testing.T, c *client) models.RegisterResponse {
	t.Helper()
	rr := c.do(http.MethodPost, models.PathRegister, models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "register phase 1")
	var phase1 models.RegisterResponse
	decode(t, rr, &phase1)
	return phase1
}

// confirmFrom runs registration phase 2 from c with pendingToken and a fresh proof of work.
func confirmFrom(c *client, pendingToken string) *httptest.ResponseRecorder {
	c.t.Helper()
	return c.do(http.MethodPost, models.PathRegister, models.RegisterRequest{Confirm: true, PendingToken: pendingToken, PoW: c.solvePoW()})
}

// scenario is one named negative-use sequence, run against a fresh server and database.
type scenario struct {
	name string
	run  func(t *testing.T, mux http.Handler)
}

func runScenarios(t *testing.T, scenarios []scenario) {
	t.Helper()
	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			s.run(t, setup(t))
		})
	}
}

// conversationView is u's listing entry of conv (it must be listed).
func conversationView(t *testing.T, u *user, conv string) *models.ConversationDTO {
	t.Helper()
	view := findConversation(listOf(t, u), conv)
	if view == nil {
		t.Fatalf("conversation is not listed")
	}
	return view
}

// messagesOf is u's latest page of conv (it must answer 200).
func messagesOf(t *testing.T, u *user, conv string) []models.MessageDTO {
	t.Helper()
	rr := u.do(http.MethodGet, models.PathConversations+"/"+conv+"/"+models.SubMessages, nil)
	expectStatus(t, rr, http.StatusOK, "messages")
	var page models.MessagesResponse
	decode(t, rr, &page)
	return page.Messages
}
