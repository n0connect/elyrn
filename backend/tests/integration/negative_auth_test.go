package integration

// Negative use: authorisation back doors. Every authenticated route of the contract table is
// called with everything that is not a live session; every conversation-scoped route is called
// by a valid account against what it is not a member of, and must answer exactly what it answers
// for something that does not exist (no existence oracle).

import (
	"net/http"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/database"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// requester builds the client of one non-session class, fresh for every request (a refused
// stale cookie is cleared by the answer, which would turn the next request into "no session").
type requester struct {
	name string
	make func() *client
}

// TestNegative_EveryProtectedRouteRefusesEveryNonSession: no session, the session that logged
// out, another device's session after logout-all, a pending-registration token as a session, a
// live session token sent as a Bearer header instead of the cookie, and the session of an account
// that was deleted. Each answers the registered 401 E_NO_SESSION on every protected route of the
// table (paging cursors included), and nothing is stored, changed or erased.
func TestNegative_EveryProtectedRouteRefusesEveryNonSession(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := uuid.MustParse(pair(t, alice, bob))
	room := createRoom(t, alice, 4, 24)
	joinRoom(t, bob, room.code)

	// Two sessions of alice; logout from one revokes both (session epoch)
	otherDevice := loginAgain(t, mux, alice)
	loggedOut := alice.cookie.Value
	expectStatus(t, alice.do(http.MethodPost, models.PathLogout, nil), http.StatusOK, "logout")
	live := loginAgain(t, mux, alice)
	alice.client = live

	pending := registerPhase1(t, newClient(t, mux)).PendingToken

	// A deleted account's last session
	doomed := register(t, mux)
	deleted := doomed.cookie.Value
	expectStatus(t, doomed.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: doomed.authKey}),
		http.StatusOK, "delete the doomed account")

	requesters := []requester{
		{"no session", func() *client { return newClient(t, mux) }},
		{"the session that logged out", func() *client { return withCookie(t, mux, loggedOut) }},
		{"another device after logout-all", func() *client { return withCookie(t, mux, otherDevice.cookie.Value) }},
		{"a pending-registration token as the cookie", func() *client { return withCookie(t, mux, pending) }},
		{"a deleted account's session", func() *client { return withCookie(t, mux, deleted) }},
	}
	bodies := shapedBodies(t, mux, alice)
	note := uuid.New()
	before := countRows(t)
	cases := 0
	for _, r := range protectedRoutes(t) {
		for _, who := range requesters {
			rr := who.make().do(r.op.Method, r.path(t, conv, note), bodyFor(r, bodies))
			expectAnswer(t, rr, apperr.NoSession, who.name+": "+r.label())
			cases++
		}
		// The live session token, sent as a header instead of the cookie
		bearer := newClient(t, mux).doWithHeaders(r.op.Method, r.path(t, conv, note), bodyFor(r, bodies),
			map[string]string{headerAuthorization: bearerPrefix + live.cookie.Value})
		expectAnswer(t, bearer, apperr.NoSession, "a Bearer header: "+r.label())
		cases++
	}
	t.Logf("%d refusals", cases)
	expectRowsUnchanged(t, before, "the refused requests")

	// The live session still works and sees everything as it was
	if n := len(listOf(t, alice)); n != 2 {
		t.Fatalf("alice lists %d conversations after the refusals, want 2", n)
	}
	if n := len(room.members(t)); n != 2 {
		t.Fatalf("the room has %d members after the refusals, want 2", n)
	}
}

// A session token is not a pending-registration token: phase 2 with it (and a valid proof of
// work) answers the registered 401 and creates nothing.
func TestNegative_ASessionTokenIsNotAPendingToken(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	before := countRows(t)
	c := newClient(t, mux)
	expectAnswer(t, confirmFrom(c, alice.cookie.Value), apperr.PendingTokenInvalid, "phase 2 with a session token")
	expectRowsUnchanged(t, before, "phase 2 with a session token")
}

// target is one conversation id a stranger may address.
type target struct {
	name string
	conv uuid.UUID
	note uuid.UUID
}

// TestNegative_NotYoursAnswersExactlyLikeNothing: mallory, a valid account, addresses alice and
// bob's pair conversation, their live room (with a note waiting for bob), an expired room, a
// burned conversation and a room she left, through every conversation-scoped route of the table
// (every method, both paging cursors), and the room routes with both message formats. Each
// answer is byte for byte the answer for an id that never existed (404 E_NOT_FOUND), and
// nothing anywhere changes.
func TestNegative_NotYoursAnswersExactlyLikeNothing(t *testing.T) {
	mux := setup(t)
	alice, bob, mallory := register(t, mux), register(t, mux), register(t, mux)
	conv := uuid.MustParse(pair(t, alice, bob))
	room := createRoom(t, alice, 4, 24)
	bobSide := joinRoom(t, bob, room.code)
	room.say(t, "for members only", 1)
	noteID, note := room.note(t, bobSide, "noaddx:x")
	expectStatus(t, room.postNote(noteID, bobSide.member.Card, note), http.StatusCreated, "a note for bob")

	expired := createRoom(t, alice, 4, 24)
	database.DB.Model(&models.Room{}).Where("id = ?", expired.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	burned := uuid.MustParse(pair(t, alice, bob))
	expectStatus(t, alice.do(http.MethodDelete, models.PathConversations+"/"+burned.String(), nil), http.StatusNoContent, "burn")
	left := createRoom(t, alice, 4, 24)
	gone := joinRoom(t, mallory, left.code)
	expectStatus(t, mallory.do(http.MethodDelete, gone.path(""), nil), http.StatusNoContent, "mallory leaves")

	targets := []target{
		{"their pair conversation", conv, uuid.New()},
		{"their live room", room.room.ID, uuid.MustParse(noteID)},
		{"an expired room", expired.room.ID, uuid.New()},
		{"a burned conversation", burned, uuid.New()},
		{"a room she left", left.room.ID, uuid.New()},
	}
	bodies := shapedBodies(t, mux, mallory)
	// A room message of the right shape (sealed by mallory in a room of her own) as the second
	// format every send is tried with
	ownRoom := createRoom(t, mallory, 4, 24)
	roomBlobID := newMessageID()
	roomBlob := models.SendMessageRequest{ID: roomBlobID, Ciphertext: ownRoom.sealTo(t, ownRoom.roster(t), roomBlobID, "x", 1)}

	before := countRows(t)
	bobView := conversationView(t, bob, room.room.ID.String())
	cases := 0
	for _, r := range conversationRoutes(t) {
		variants := []any{bodyFor(r, bodies)}
		if r.op.Method == http.MethodPost && r.template == models.PathConversations+"/"+templateConversation+"/"+models.SubMessages {
			variants = append(variants, roomBlob)
		}
		for _, body := range variants {
			reference := mallory.do(r.op.Method, r.path(t, uuid.New(), uuid.New()), body)
			expectAnswer(t, reference, apperr.NotFound, "nothing: "+r.label())
			for _, tg := range targets {
				rr := mallory.do(r.op.Method, r.path(t, tg.conv, tg.note), body)
				expectIdentical(t, rr, reference, tg.name+": "+r.label())
				cases++
			}
		}
	}
	t.Logf("%d answers compared", cases)
	expectRowsUnchanged(t, before, "the stranger's requests")
	after := conversationView(t, bob, room.room.ID.String())
	if after.LastSeq != bobView.LastSeq || after.ReadSeq != bobView.ReadSeq || after.Room.Members != 2 || after.Room.Notes != 1 {
		t.Fatalf("bob's view of the room changed: %+v, before %+v", after, bobView)
	}
	if got := bobSide.read(t); len(got) != 1 || got[0].text != "for members only" {
		t.Fatalf("bob reads %+v", got)
	}
}

// The answers compared above are only as good as their reference: an id that never existed
// answers the same as a malformed id under the conversations path would not (that is the
// gate's 404), so the reference itself is pinned to the chat 404 here, against both.
func TestNegative_NothingIsTheChat404NotTheRoute404(t *testing.T) {
	mux := setup(t)
	mallory := register(t, mux)
	nothing := mallory.do(http.MethodGet, models.PathConversations+"/"+uuid.NewString()+"/"+models.SubMessages, nil)
	expectAnswer(t, nothing, apperr.NotFound, "an unknown conversation")
	malformed := mallory.do(http.MethodGet, models.PathConversations+"/not-a-uuid/"+models.SubMessages, nil)
	expectAnswer(t, malformed, apperr.RouteNotFound, "a malformed conversation id")
	if nothing.Body.String() == malformed.Body.String() {
		t.Fatal("the reference does not tell the chat 404 from the route 404: the comparisons above prove nothing")
	}
}
