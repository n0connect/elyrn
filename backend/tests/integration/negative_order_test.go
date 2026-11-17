package integration

// Negative use: the right calls in the wrong order, or more than once. Each scenario runs on a
// fresh database, asserts the exact registered answer of every refusal and re-reads the state
// it must have left alone.

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/database"
	"elyrn/internal/identity"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

const (
	// concurrentRedeemers race for one invite
	concurrentRedeemers = 4
	// staleRosterAttempts: a sender that keeps the stale roster keeps being refused
	staleRosterAttempts = 3
	// forgedPendingToken has the JWS shape the gate admits and no valid signature
	forgedPendingToken = "eyJhbGciOiJIUzI1NiJ9.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestNegative_RegistrationOutOfOrder(t *testing.T) {
	runScenarios(t, []scenario{
		{"phase 2 before phase 1", func(t *testing.T, mux http.Handler) {
			c := newClient(t, mux)
			expectAnswer(t, confirmFrom(c, ""), apperr.PendingTokenRequired, "phase 2 without a pending token")
			expectAnswer(t, confirmFrom(c, forgedPendingToken), apperr.PendingTokenInvalid, "phase 2 with a forged token")
			expectRows(t, &models.User{}, 0, "phase 2 before phase 1")
		}},
		{"phase 2 twice", func(t *testing.T, mux http.Handler) {
			c := newClient(t, mux)
			phase1 := registerPhase1(t, c)
			expectStatus(t, confirmFrom(c, phase1.PendingToken), http.StatusCreated, "phase 2")
			expectAnswer(t, confirmFrom(c, phase1.PendingToken), apperr.PendingTokenInvalid, "phase 2 again")
			expectRows(t, &models.User{}, 1, "phase 2 twice")
		}},
		// The pending token is a bearer secret, as designed (not bound to the client that asked
		// for it): whoever confirms it gets the account whose number phase 1 showed, once
		{"a phase-1 token confirmed from another client", func(t *testing.T, mux http.Handler) {
			asked, other := newClient(t, mux), newClient(t, mux)
			phase1 := registerPhase1(t, asked)
			expectStatus(t, confirmFrom(other, phase1.PendingToken), http.StatusCreated, "phase 2 from another client")
			expectAnswer(t, confirmFrom(asked, phase1.PendingToken), apperr.PendingTokenInvalid, "phase 2 from the asking client")
			expectRows(t, &models.User{}, 1, "one token, two confirmations")
			rr := other.do(http.MethodGet, models.PathMe, nil)
			expectStatus(t, rr, http.StatusOK, "me")
			var me models.MeResponse
			decode(t, rr, &me)
			want, err := identity.DerivePublicKey(phase1.AccountNumber)
			if err != nil || me.PublicKey != want {
				t.Fatalf("the confirmed account is not the one phase 1 showed: %v", err)
			}
		}},
		{"login before phase 2", func(t *testing.T, mux http.Handler) {
			c := newClient(t, mux)
			phase1 := registerPhase1(t, c)
			key := registeredAuthKey(t, phase1.AccountNumber)
			expectAnswer(t, newClient(t, mux).do(http.MethodPost, models.PathLogin, models.LoginRequest{AuthKey: key}),
				apperr.LoginNoAccount, "login before phase 2")
			expectRows(t, &models.User{}, 0, "login before phase 2")
			expectStatus(t, confirmFrom(c, phase1.PendingToken), http.StatusCreated, "phase 2 after the refused login")
			expectStatus(t, newClient(t, mux).do(http.MethodPost, models.PathLogin, models.LoginRequest{AuthKey: key}),
				http.StatusOK, "login after phase 2")
		}},
	})
}

// Proofs of work are single use across every endpoint, and not bound to a purpose (the design:
// pow.ValidateSolution spends a challenge in one process-wide set whatever the action; the
// action names only the log line), so a spent one is refused everywhere and nothing is created.
func TestNegative_ProofOfWorkReuse(t *testing.T) {
	runScenarios(t, []scenario{
		{"the same solution twice on one endpoint", func(t *testing.T, mux http.Handler) {
			alice := register(t, mux)
			paid := models.CreateInviteRequest{PoW: alice.freshPoW()}
			expectStatus(t, alice.do(http.MethodPost, models.PathInvites, paid), http.StatusCreated, "invite")
			expectAnswer(t, alice.do(http.MethodPost, models.PathInvites, paid), apperr.PoWInvalid, "the replayed invite")
			expectRows(t, &models.Invite{}, 1, "a replayed proof of work")
		}},
		{"spent on registration, then on an invite", func(t *testing.T, mux http.Handler) {
			alice := register(t, mux)
			c := newClient(t, mux)
			solution := c.solvePoW()
			expectStatus(t, c.do(http.MethodPost, models.PathRegister, models.RegisterRequest{PoW: solution}), http.StatusOK, "phase 1")
			expectAnswer(t, alice.do(http.MethodPost, models.PathInvites, models.CreateInviteRequest{PoW: solution}),
				apperr.PoWInvalid, "an invite paid with a registration's proof")
			expectRows(t, &models.Invite{}, 0, "a reused proof of work")
		}},
		{"spent on an invite, then on a room", func(t *testing.T, mux http.Handler) {
			alice := register(t, mux)
			solution := alice.freshPoW()
			expectStatus(t, alice.do(http.MethodPost, models.PathInvites, models.CreateInviteRequest{PoW: solution}), http.StatusCreated, "invite")
			req := sideOf(t, alice, newCode(t, 4, 24)).createRequest(t)
			req.PoW = solution
			expectAnswer(t, alice.do(http.MethodPost, models.PathRooms, req), apperr.PoWInvalid, "a room paid with an invite's proof")
			expectRows(t, &models.Room{}, 0, "a reused proof of work")
		}},
	})
}

// redeemToken creates an invite of creator and returns its token.
func redeemToken(t *testing.T, creator *user) string {
	t.Helper()
	rr := creator.createInvite()
	expectStatus(t, rr, http.StatusCreated, "invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)
	return invite.Token
}

func redeem(u *user, token string) *httptest.ResponseRecorder {
	return u.do(http.MethodPost, models.PathInvitesRedeem, models.RedeemInviteRequest{Token: token})
}

func TestNegative_InvitesRedeemedWrongly(t *testing.T) {
	runScenarios(t, []scenario{
		{"redeemed twice in a row", func(t *testing.T, mux http.Handler) {
			alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
			token := redeemToken(t, alice)
			expectStatus(t, redeem(bob, token), http.StatusCreated, "redeem")
			expectAnswer(t, redeem(carol, token), apperr.NotFound, "redeem again by another")
			expectAnswer(t, redeem(bob, token), apperr.NotFound, "redeem again by the redeemer")
			expectRows(t, &models.Conversation{}, 1, "one invite redeemed thrice")
		}},
		{"redeemed concurrently", func(t *testing.T, mux http.Handler) {
			alice := register(t, mux)
			redeemers := make([]*user, concurrentRedeemers)
			for i := range redeemers {
				redeemers[i] = register(t, mux)
			}
			token := redeemToken(t, alice)
			answers := make([]*httptest.ResponseRecorder, len(redeemers))
			start := make(chan struct{})
			var wg sync.WaitGroup
			for i, u := range redeemers {
				wg.Add(1)
				go func(i int, u *user) {
					defer wg.Done()
					<-start
					answers[i] = redeem(u, token)
				}(i, u)
			}
			close(start)
			wg.Wait()
			won := 0
			for i, rr := range answers {
				if rr.Code == http.StatusCreated {
					won++
					continue
				}
				expectAnswer(t, rr, apperr.NotFound, "a losing redeemer "+strconv.Itoa(i))
			}
			if won != 1 {
				t.Fatalf("%d redeemers won one invite", won)
			}
			expectRows(t, &models.Conversation{}, 1, "a raced invite")
			expectRows(t, &models.Invite{}, 0, "a raced invite")
		}},
		{"redeemed by its creator", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			token := redeemToken(t, alice)
			expectAnswer(t, redeem(alice, token), apperr.NotFound, "the creator redeems")
			expectRows(t, &models.Invite{}, 1, "the creator's refused redeem consumed the invite")
			expectStatus(t, redeem(bob, token), http.StatusCreated, "the invite still works for another")
		}},
	})
}

// roomPath is the path of one room's sub-resource.
func roomPath(s *roomSide, sub string) string {
	if sub == "" {
		return s.path("")
	}
	return s.path("/" + sub)
}

func TestNegative_RoomsInTheWrongOrder(t *testing.T) {
	runScenarios(t, []scenario{
		{"join twice", func(t *testing.T, mux http.Handler) {
			a, b := roomOfTwo(t, mux)
			bob := b.u
			expectStatus(t, bob.do(http.MethodPost, models.PathRoomsJoin, b.joinRequest(t)), http.StatusOK, "join again")
			if n := len(a.members(t)); n != 2 {
				t.Fatalf("join twice left %d members", n)
			}
		}},
		{"join after leaving: a new seat that reads only what follows", func(t *testing.T, mux http.Handler) {
			a, b := roomOfTwo(t, mux)
			bob := b.u
			a.say(t, "while bob is in", 1)
			expectStatus(t, bob.do(http.MethodDelete, roomPath(b, ""), nil), http.StatusNoContent, "leave")
			a.say(t, "while bob is out", 2)
			back := joinRoom(t, bob, a.code)
			a.say(t, "after bob came back", 3)
			if got := back.read(t); len(got) != 1 || got[0].text != "after bob came back" {
				t.Fatalf("bob reads %+v after rejoining", got)
			}
			if n := len(a.members(t)); n != 2 {
				t.Fatalf("%d members after a rejoin", n)
			}
		}},
		{"join after burn", func(t *testing.T, mux http.Handler) {
			alice, carol := register(t, mux), register(t, mux)
			a := createRoom(t, alice, 4, 24)
			expectStatus(t, alice.do(http.MethodDelete, roomPath(a, ""), nil), http.StatusNoContent, "burn")
			expectAnswer(t, carol.do(http.MethodPost, models.PathRoomsJoin, sideOf(t, carol, a.code).joinRequest(t)), apperr.NotFound, "join a burned room")
			expectRows(t, &models.Room{}, 0, "join after burn")
			expectRows(t, &models.ConversationMember{}, 0, "join after burn")
		}},
		{"leave twice", func(t *testing.T, mux http.Handler) {
			a, b := roomOfTwo(t, mux)
			bob := b.u
			expectStatus(t, bob.do(http.MethodDelete, roomPath(b, ""), nil), http.StatusNoContent, "leave")
			expectAnswer(t, bob.do(http.MethodDelete, roomPath(b, ""), nil), apperr.NotFound, "leave again")
			if n := len(a.members(t)); n != 1 {
				t.Fatalf("%d members after leaving twice", n)
			}
		}},
		{"burn twice", func(t *testing.T, mux http.Handler) {
			alice := register(t, mux)
			a := createRoom(t, alice, 4, 24)
			expectStatus(t, alice.do(http.MethodDelete, roomPath(a, ""), nil), http.StatusNoContent, "burn")
			expectAnswer(t, alice.do(http.MethodDelete, roomPath(a, ""), nil), apperr.NotFound, "burn again")
		}},
		{"a non-owner's burn is a leave", func(t *testing.T, mux http.Handler) {
			a, b := roomOfTwo(t, mux)
			alice, bob := a.u, b.u
			expectStatus(t, bob.do(http.MethodDelete, roomPath(b, ""), nil), http.StatusNoContent, "bob burns")
			expectRows(t, &models.Room{}, 1, "a non-owner's burn")
			if view := conversationView(t, alice, a.room.ID.String()); view.Room.Members != 1 {
				t.Fatalf("the owner sees %d members", view.Room.Members)
			}
		}},
		{"send to a burned, a left and an expired conversation", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			conv := pair(t, alice, bob)
			expectStatus(t, alice.do(http.MethodDelete, models.PathConversations+"/"+conv, nil), http.StatusNoContent, "burn")
			id := newMessageID()
			expectAnswer(t, bob.do(http.MethodPost, models.PathConversations+"/"+conv+"/"+models.SubMessages,
				models.SendMessageRequest{ID: id, Ciphertext: pairCiphertext(t)}), apperr.NotFound, "send to a burned pair")

			a := createRoom(t, alice, 4, 24)
			b := joinRoom(t, bob, a.code)
			roster := a.roster(t)
			expectStatus(t, bob.do(http.MethodDelete, roomPath(b, ""), nil), http.StatusNoContent, "leave")
			expectAnswer(t, b.post(id, b.sealTo(t, roster, id, "after leaving", 1)), apperr.NotFound, "send to a left room")

			database.DB.Model(&models.Room{}).Where("id = ?", a.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
			expectAnswer(t, a.post(id, a.sealTo(t, []string{a.member.Card}, id, "too late", 1)), apperr.NotFound, "send to an expired room")
			expectRows(t, &models.Message{}, 0, "sends nobody could receive")
		}},
	})
}

func TestNegative_MessagesRepeated(t *testing.T) {
	runScenarios(t, []scenario{
		{"the same id twice, same and other content", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			conv := pair(t, alice, bob)
			path := models.PathConversations + "/" + conv + "/" + models.SubMessages
			id := newMessageID()
			first := seal(t, alice, bob, conv, id, "first", 1)
			expectStatus(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: id, Ciphertext: first}), http.StatusCreated, "send")
			expectAnswer(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: id, Ciphertext: first}), apperr.Conflict, "resend")
			other := seal(t, alice, bob, conv, id, "other", 2)
			// Other content under a held id is not the earlier attempt: id taken, never "stored"
			expectAnswer(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: id, Ciphertext: other}), apperr.IDTaken, "same id, other content")
			stored := messagesOf(t, bob, conv)
			if len(stored) != 1 || stored[0].Ciphertext != first || stored[0].Seq != 1 {
				t.Fatalf("stored %+v, want only the first ciphertext at seq 1", stored)
			}
			if view := conversationView(t, bob, conv); view.LastSeq != 1 {
				t.Fatalf("last_seq %d after refused resends", view.LastSeq)
			}
		}},
		{"a stale roster, again and again", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			a := createRoom(t, alice, 4, 24)
			stale := a.roster(t)
			joinRoom(t, bob, a.code)
			id := newMessageID()
			for attempt := 0; attempt < staleRosterAttempts; attempt++ {
				expectAnswer(t, a.post(id, a.sealTo(t, stale, id, "bob would miss this", 1)), apperr.RosterChanged, "stale send "+strconv.Itoa(attempt))
			}
			expectRows(t, &models.Message{}, 0, "stale sends")
			if view := conversationView(t, alice, a.room.ID.String()); view.LastSeq != 0 {
				t.Fatalf("refused sends moved last_seq to %d", view.LastSeq)
			}
		}},
		{"mark-read beyond the end and backwards", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			conv := pair(t, alice, bob)
			send(t, alice, bob, conv, 1)
			send(t, alice, bob, conv, 2)
			path := models.PathConversations + "/" + conv + "/read"
			expectAnswer(t, bob.do(http.MethodPost, path, models.MarkReadRequest{Seq: 3}), apperr.InvalidInput, "mark past the end")
			if view := conversationView(t, bob, conv); view.ReadSeq != 0 {
				t.Fatalf("a refused mark moved read_seq to %d", view.ReadSeq)
			}
			expectStatus(t, bob.do(http.MethodPost, path, models.MarkReadRequest{Seq: 2}), http.StatusNoContent, "mark the end")
			expectStatus(t, bob.do(http.MethodPost, path, models.MarkReadRequest{Seq: 1}), http.StatusNoContent, "mark backwards")
			if view := conversationView(t, bob, conv); view.ReadSeq != 2 {
				t.Fatalf("marking backwards moved read_seq to %d", view.ReadSeq)
			}
		}},
	})
}

// TestNegative_PagingCursorsOutOfRange: cursors past either end answer an empty page; both
// cursors at once, a cursor below its range, a signed, overflowing or non-canonical number, or
// a repeated cursor is refused by the gate (400), and nothing is read for it.
func TestNegative_PagingCursorsOutOfRange(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	send(t, alice, bob, conv, 2)
	base := models.PathConversations + "/" + conv + "/" + models.SubMessages + "?"
	empty := []string{"after=2", "after=9223372036854775807", "before=1"}
	for _, q := range empty {
		rr := bob.do(http.MethodGet, base+q, nil)
		expectStatus(t, rr, http.StatusOK, q)
		var page models.MessagesResponse
		decode(t, rr, &page)
		if len(page.Messages) != 0 {
			t.Fatalf("%s served %d messages", q, len(page.Messages))
		}
	}
	refused := []string{"after=0&before=2", "before=0", "after=-1", "after=9223372036854775808", "after=01", "after=1&after=1", "after=1.0", "after="}
	for _, q := range refused {
		expectAnswer(t, bob.do(http.MethodGet, base+q, nil), apperr.InvalidRequest, q)
	}
}

func TestNegative_AccountDeletedWrongly(t *testing.T) {
	runScenarios(t, []scenario{
		{"delete twice", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			session := alice.cookie.Value
			expectStatus(t, alice.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: alice.authKey}), http.StatusOK, "delete")
			expectAnswer(t, withCookie(t, mux, session).do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: alice.authKey}),
				apperr.NoSession, "delete again")
			expectRows(t, &models.User{}, 1, "delete twice")
			expectStatus(t, bob.do(http.MethodGet, models.PathMe, nil), http.StatusOK, "the other account")
		}},
		{"another account's key, and one's own account number for the key", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			pair(t, alice, bob)
			expectStatus(t, alice.createInvite(), http.StatusCreated, "a pending invite")
			before := countRows(t)
			for name, key := range map[string]string{"bob's auth key": bob.authKey, "alice's own account number": alice.accountNumber} {
				expectAnswer(t, alice.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: key}), apperr.Forbidden, name)
			}
			expectRowsUnchanged(t, before, "refused deletions")
			expectStatus(t, alice.do(http.MethodGet, models.PathMe, nil), http.StatusOK, "alice is still there")
		}},
	})
}

func TestNegative_NotesMisaddressed(t *testing.T) {
	mux := setup(t)
	a, b, c := roomOfThree(t, mux)
	carol := c.u
	noteID, note := a.note(t, b, "noaddx:x")
	expectStatus(t, a.postNote(noteID, b.member.Card, note), http.StatusCreated, "a note for bob")
	outsider := sideOf(t, register(t, mux), a.code)
	before := countRows(t)

	selfID, toSelf := a.note(t, a, "noaddx:x")
	expectAnswer(t, a.postNote(selfID, a.member.Card, toSelf), apperr.InvalidInput, "a note to oneself")
	outID, toOut := a.note(t, outsider, "noaddx:x")
	expectAnswer(t, a.postNote(outID, outsider.member.Card, toOut), apperr.NotFound, "a note to a non-member")

	// Carol dismissing bob's note answers exactly like dismissing a note that never existed
	reference := carol.do(http.MethodDelete, roomPath(c, "notes/"+uuid.NewString()), nil)
	expectAnswer(t, reference, apperr.NotFound, "dismiss a note that never existed")
	expectIdentical(t, carol.do(http.MethodDelete, roomPath(c, "notes/"+noteID), nil), reference, "dismiss bob's note")
	expectRowsUnchanged(t, before, "misaddressed notes")
	if got := b.notes(t); len(got) != 1 || got[0].ID != noteID {
		t.Fatalf("bob's notes %+v", got)
	}

	// A note to a member who has left
	expectStatus(t, carol.do(http.MethodDelete, roomPath(c, ""), nil), http.StatusNoContent, "carol leaves")
	leftID, toLeft := a.note(t, c, "noaddx:x")
	expectAnswer(t, a.postNote(leftID, c.member.Card, toLeft), apperr.NotFound, "a note to a member who left")
	expectRows(t, &models.RoomNote{}, 1, "a note to a member who left")
}
