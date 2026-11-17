package integration

// Negative use: cross-protocol confusion. Values of the right shape in the wrong place: a room
// blob where a pair ciphertext belongs and back, a note as a message and back, a card where a
// vault belongs, an invite token as a room id, ids of the right shape but the wrong kind,
// another conversation's message id, another room's message. Every refusal is the exact
// registered answer, and nothing is stored for it.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// confusion is one request built from the shared world, with the answer it must get.
type confusion struct {
	name string
	send func() *httptest.ResponseRecorder
	want apperr.Code
}

func TestNegative_CrossProtocolConfusion(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	a := createRoom(t, alice, 2, 24)
	b := joinRoom(t, bob, a.code)
	other := createRoom(t, alice, 2, 24)
	joinRoom(t, bob, other.code)
	noteID, note := a.note(t, b, "noaddx:x")
	expectStatus(t, a.postNote(noteID, b.member.Card, note), http.StatusCreated, "a note")
	token := redeemToken(t, alice)

	pairPath := models.PathConversations + "/" + conv + "/" + models.SubMessages
	pairID := newMessageID()
	pairMessage := seal(t, alice, bob, conv, pairID, "one-to-one", 1)
	roomID := newMessageID()
	roomMessage := a.sealTo(t, a.roster(t), roomID, "room", 1)
	otherRoomID := newMessageID()
	otherRoomMessage := other.sealTo(t, other.roster(t), otherRoomID, "other room", 1)
	strayNoteID, strayNote := a.note(t, b, "noaddx:stray")

	vaultAsCard := a.joinRequest(t)
	vaultAsCard.Card = vaultAsCard.Vault
	cardAsVault := a.joinRequest(t)
	cardAsVault.Vault = cardAsVault.Card
	tokenAsRoomID := a.joinRequest(t)
	tokenAsRoomID.ID = token
	authKeyAsLookup := b.joinRequest(t)
	authKeyAsLookup.Lookup = bob.authKey
	lookupAsAuthKey := models.LoginRequest{AuthKey: a.room.Lookup}

	cases := []confusion{
		{"a room message in a pair conversation", func() *httptest.ResponseRecorder {
			return alice.do(http.MethodPost, pairPath, models.SendMessageRequest{ID: roomID, Ciphertext: roomMessage})
		}, apperr.InvalidInput},
		{"a pair message in a room", func() *httptest.ResponseRecorder {
			return a.post(pairID, pairMessage)
		}, apperr.InvalidInput},
		{"a note as a message", func() *httptest.ResponseRecorder {
			return a.post(strayNoteID, strayNote)
		}, apperr.InvalidRequest},
		{"a room message as a note", func() *httptest.ResponseRecorder {
			return a.postNote(roomID, b.member.Card, roomMessage)
		}, apperr.InvalidRequest},
		{"a pair message as a note", func() *httptest.ResponseRecorder {
			return a.postNote(pairID, b.member.Card, pairMessage)
		}, apperr.InvalidRequest},
		// Sealed for the other room's roster: the digest is not this room's (412, re-fetch)
		{"another room's message", func() *httptest.ResponseRecorder {
			return a.post(otherRoomID, otherRoomMessage)
		}, apperr.RosterChanged},
		{"a vault in the card field", func() *httptest.ResponseRecorder {
			return alice.do(http.MethodPost, models.PathRoomsJoin, vaultAsCard)
		}, apperr.InvalidRequest},
		{"a card in the vault field", func() *httptest.ResponseRecorder {
			return alice.do(http.MethodPost, models.PathRoomsJoin, cardAsVault)
		}, apperr.InvalidRequest},
		{"an invite token as a room id", func() *httptest.ResponseRecorder {
			return alice.do(http.MethodPost, models.PathRoomsJoin, tokenAsRoomID)
		}, apperr.InvalidRequest},
		{"a room id as an invite token", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodPost, models.PathInvitesRedeem, models.RedeemInviteRequest{Token: a.room.ID.String()})
		}, apperr.InvalidRequest},
		{"an auth key as a room lookup", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodPost, models.PathRoomsJoin, authKeyAsLookup)
		}, apperr.NotFound},
		{"a room lookup as an auth key", func() *httptest.ResponseRecorder {
			return newClient(t, mux).do(http.MethodPost, models.PathLogin, lookupAsAuthKey)
		}, apperr.LoginNoAccount},
		{"a note id as a conversation id", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodGet, models.PathConversations+"/"+noteID+"/"+models.SubMessages, nil)
		}, apperr.NotFound},
		{"a conversation id as a note id", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodDelete, b.path("/notes/"+conv), nil)
		}, apperr.NotFound},
		{"a pending note's id as another room's note", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodDelete, models.PathConversations+"/"+other.room.ID.String()+"/notes/"+noteID, nil)
		}, apperr.NotFound},
		{"a pair conversation's members", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodGet, models.PathConversations+"/"+conv+"/members", nil)
		}, apperr.NotFound},
		{"a pair conversation's notes", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodGet, models.PathConversations+"/"+conv+"/notes", nil)
		}, apperr.NotFound},
		{"an invite token in the conversation path", func() *httptest.ResponseRecorder {
			return bob.do(http.MethodGet, models.PathConversations+"/"+token+"/"+models.SubMessages, nil)
		}, apperr.RouteNotFound},
	}
	before := countRows(t)
	for _, c := range cases {
		expectAnswer(t, c.send(), c.want, c.name)
	}
	expectRowsUnchanged(t, before, "the confused requests")
	if n := len(b.notes(t)); n != 1 {
		t.Fatalf("bob has %d notes after the confused requests, want 1", n)
	}
}

// firstMessageStored pairs alice and bob, and alice's first message to bob is stored under a
// fresh id; it returns both, the conversation, the id and the stored ciphertext.
func firstMessageStored(t *testing.T, mux http.Handler) (alice, bob *user, conv, id, first string) {
	t.Helper()
	alice, bob = register(t, mux), register(t, mux)
	conv = pair(t, alice, bob)
	id = newMessageID()
	first = seal(t, alice, bob, conv, id, "first", 1)
	expectStatus(t, alice.do(http.MethodPost, messagesPath(conv), models.SendMessageRequest{ID: id, Ciphertext: first}), http.StatusCreated, "send")
	return alice, bob, conv, id, first
}

// A message id is unique on the whole server (models.Message.ID: uniqueIndex), not per
// conversation. A duplicate id answers 409 Conflict, the documented "your earlier attempt is
// stored", only for the caller's own identical message in the same conversation (a resend after a
// lost answer); every other holder answers 409 IdTaken (send again under a fresh id), and neither
// stores anything. Both are 409, and only to a member of the conversation in the path, so the split
// adds no existence oracle (chat/duplicates.go). Honest clients draw a fresh UUIDv4 per message.
func TestNegative_AnotherConversationsMessageID(t *testing.T) {
	runScenarios(t, []scenario{
		{"the same id and content after a lost answer is stored", func(t *testing.T, mux http.Handler) {
			alice, bob, conv, id, first := firstMessageStored(t, mux)
			before := countRows(t)
			expectAnswer(t, alice.do(http.MethodPost, messagesPath(conv), models.SendMessageRequest{ID: id, Ciphertext: first}), apperr.Conflict, "the resend")
			expectRowsUnchanged(t, before, "the resend")
			expectOnlyMessage(t, bob, conv, id, first)
		}},
		{"the same id with other content is taken", func(t *testing.T, mux http.Handler) {
			alice, bob, conv, id, first := firstMessageStored(t, mux)
			before := countRows(t)
			expectAnswer(t, alice.do(http.MethodPost, messagesPath(conv), models.SendMessageRequest{ID: id, Ciphertext: seal(t, alice, bob, conv, id, "other", 2)}),
				apperr.IDTaken, "other content under the id")
			expectRowsUnchanged(t, before, "other content under the id")
			expectOnlyMessage(t, bob, conv, id, first)
		}},
		{"another conversation's id is taken", func(t *testing.T, mux http.Handler) {
			alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
			first := pair(t, alice, bob)
			second := pair(t, alice, carol)
			id := newMessageID()
			stored := seal(t, alice, bob, first, id, "first", 1)
			expectStatus(t, alice.do(http.MethodPost, messagesPath(first), models.SendMessageRequest{ID: id, Ciphertext: stored}), http.StatusCreated, "send")
			before := countRows(t)
			expectAnswer(t, alice.do(http.MethodPost, messagesPath(second), models.SendMessageRequest{ID: id, Ciphertext: seal(t, alice, carol, second, id, "second", 1)}),
				apperr.IDTaken, "the same id elsewhere")
			// Byte for byte the stored ciphertext, in the other conversation: still not the same send
			expectAnswer(t, alice.do(http.MethodPost, messagesPath(second), models.SendMessageRequest{ID: id, Ciphertext: stored}),
				apperr.IDTaken, "the same id and bytes elsewhere")
			expectRowsUnchanged(t, before, "a reused id")
			if view := conversationView(t, carol, second); view.LastSeq != 0 {
				t.Fatalf("a refused send moved last_seq to %d", view.LastSeq)
			}
			expectOnlyMessage(t, bob, first, id, stored)
		}},
		{"another member's id in the same room is taken", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			a := createRoom(t, alice, 3, 24)
			b := joinRoom(t, bob, a.code)
			id := newMessageID()
			stored := a.sealTo(t, a.roster(t), id, "alice's", 1)
			expectStatus(t, a.post(id, stored), http.StatusCreated, "alice sends")
			before := countRows(t)
			// bob read alice's id and bytes (every member is served them) and posts them as his
			expectAnswer(t, b.post(id, stored), apperr.IDTaken, "alice's message posted by bob")
			expectAnswer(t, b.post(id, b.sealTo(t, b.roster(t), id, "bob's", 1)), apperr.IDTaken, "bob's message under alice's id")
			expectRowsUnchanged(t, before, "a member's id reused by another")
			expectOnlyMessage(t, bob, a.room.ID.String(), id, stored)
		}},
		{"a stored resend is stored although the roster changed meanwhile", func(t *testing.T, mux http.Handler) {
			alice, bob := register(t, mux), register(t, mux)
			a := createRoom(t, alice, 3, 24)
			id := newMessageID()
			stored := a.sealTo(t, a.roster(t), id, "before bob", 1)
			expectStatus(t, a.post(id, stored), http.StatusCreated, "send")
			joinRoom(t, bob, a.code)
			before := countRows(t)
			// 412 here would make the client re-encrypt and resend other bytes under the id
			expectAnswer(t, a.post(id, stored), apperr.Conflict, "the resend after a join")
			expectRowsUnchanged(t, before, "the resend after a join")
		}},
		{"a note id: the same note is waiting, any other holder is taken", func(t *testing.T, mux http.Handler) {
			a, b, c := roomOfThree(t, mux)
			alice, bob := a.u, b.u
			other := createRoom(t, alice, 2, 24)
			otherB := joinRoom(t, bob, other.code)
			noteID, note := a.note(t, b, "noaddx:first")
			expectStatus(t, a.postNote(noteID, b.member.Card, note), http.StatusCreated, "a note")
			before := countRows(t)
			expectAnswer(t, a.postNote(noteID, b.member.Card, note), apperr.Conflict, "the same note again")
			_, otherBlob := a.note(t, b, "noaddx:other")
			expectAnswer(t, a.postNote(noteID, b.member.Card, otherBlob), apperr.IDTaken, "other content under the note's id")
			_, toCarol := a.note(t, c, "noaddx:carol")
			expectAnswer(t, a.postNote(noteID, c.member.Card, toCarol), apperr.IDTaken, "the id to another addressee")
			_, fromCarol := c.note(t, b, "noaddx:from carol")
			expectAnswer(t, c.postNote(noteID, b.member.Card, fromCarol), apperr.IDTaken, "the id from another member")
			_, elsewhere := other.note(t, otherB, "noaddx:elsewhere")
			expectAnswer(t, other.postNote(noteID, otherB.member.Card, elsewhere), apperr.IDTaken, "the id in another room")
			expectRowsUnchanged(t, before, "reused note ids")
			if notes := b.notes(t); len(notes) != 1 || notes[0].ID != noteID || notes[0].Blob != note {
				t.Fatalf("bob's notes %+v, want only the first", notes)
			}
		}},
	})
}

// messagesPath is the send and read path of conv.
func messagesPath(conv string) string {
	return models.PathConversations + "/" + conv + "/" + models.SubMessages
}

// expectOnlyMessage insists u's page of conv is exactly one message: id, holding ciphertext.
func expectOnlyMessage(t *testing.T, u *user, conv, id, ciphertext string) {
	t.Helper()
	stored := messagesOf(t, u, conv)
	if len(stored) != 1 || stored[0].ID != id || stored[0].Ciphertext != ciphertext {
		t.Fatalf("stored %+v, want only the original message", stored)
	}
}

// The server cannot tell a ciphertext sealed for one conversation from one sealed for another
// between the same two people (it never sees a key): it stores it. The protection is the
// client's: the conversation id is bound into the AEAD's associated data (NADM), so the reader
// cannot open it there, and nothing is ever shown for it.
func TestNegative_APairMessageSealedForAnotherConversation(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	first := pair(t, alice, bob)
	second := pair(t, alice, bob)
	id := newMessageID()
	misplaced := seal(t, alice, bob, first, id, "meant for the first", 1)
	expectStatus(t, alice.do(http.MethodPost, models.PathConversations+"/"+second+"/"+models.SubMessages,
		models.SendMessageRequest{ID: id, Ciphertext: misplaced}), http.StatusCreated, "the server stores what it cannot open")
	stored := messagesOf(t, bob, second)
	if len(stored) != 1 {
		t.Fatalf("%d messages stored", len(stored))
	}
	key, err := e2e.ConversationKey(bob.privateKey, alice.publicKey, uuid.MustParse(second))
	if err != nil {
		t.Fatalf("ConversationKey: %v", err)
	}
	if _, err := e2e.Decrypt(key, uuid.MustParse(second), uuid.MustParse(stored[0].ID), alice.publicKey, stored[0].Ciphertext); err == nil {
		t.Fatal("a message sealed for another conversation opened in this one")
	}
}
