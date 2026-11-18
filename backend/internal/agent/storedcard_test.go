package agent

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// A1 for the agent (backend/internal/chat/rooms.go:checkRoomMessage:header-card-not-bound-to-sending-member):
// the server refuses a room message whose header card is not the sender's stored card. A card is
// sealed under a random nonce, so the card this agent derives for a room differs in bytes from the
// one stored when it joined; it must seal the stored one, which the roster row flagged as its own
// carries.

// headerCardOffset and headerCardBytes locate the sender card in a room blob: magic(4) version(1) card(60)
const (
	headerCardOffset = 5
	headerCardBytes  = 60
)

func TestSend_SealsTheStoredCardNotTheDerivedOne(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	stored := fx.impostorCard(t, fuzzSelf) // this agent's key under another nonce: the card stored at join
	rows := fx.honestRows()
	rows[0].Card = stored
	if err := st.verifyMembers(rows); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	if st.member.Card != stored {
		t.Fatal("the agent keeps the card it derived, not the one the server stores for its seat")
	}
	blob, err := (&Agent{}).seal(st, uuid.New(), "hello", 1)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("decode blob: %v", err)
	}
	card, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("decode card: %v", err)
	}
	if !bytes.Equal(raw[headerCardOffset:headerCardOffset+headerCardBytes], card) {
		t.Fatal("the message header carries another card than the stored one")
	}
}

// The server's refusal is told apart by its registered message under its status only.
func TestSenderCardMismatch_IsReadFromTheServersAnswer(t *testing.T) {
	body := []byte(`{"success":false,"message":"` + serverSenderCardMismatch + `"}`)
	for _, tc := range []struct {
		ans  *answer
		want bool
	}{
		{&answer{status: http.StatusBadRequest, body: body}, true},
		{&answer{status: http.StatusConflict, body: body}, false},
		{&answer{status: http.StatusBadRequest, body: []byte(`{"message":"Bad request"}`)}, false},
		{&answer{status: http.StatusBadRequest, body: []byte(serverSenderCardMismatch)}, false},
		{nil, false},
	} {
		if got := senderCardMismatch(tc.ans); got != tc.want {
			t.Errorf("senderCardMismatch(%+v) = %v", tc.ans, got)
		}
	}
	if idTaken(&answer{status: http.StatusBadRequest, body: body}) {
		t.Fatal("a sender card mismatch read as an id taken")
	}
}
