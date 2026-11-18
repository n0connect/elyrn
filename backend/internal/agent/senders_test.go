package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// F2 (agent-room-message/sender-reported-by-12bit-name-without-code-or-roster-binding): a member
// grinds a key whose 12-bit aura name equals another member's and seals messages under it. The
// agent used to report only the name; it now reports name and code, marks a sender that is not on
// the current member list as left, and marks a name shared by two keys in view as same_name.

// maxGrindTries bounds the search for a lookalike key: one in 4096 keys shares a given name, so
// 2^16 tries miss with a probability of about e^-16
const maxGrindTries = 1 << 16

// lookalike derives, from random roots, a member key of the fixture's room whose aura name is
// member i's but whose key is not.
func (fx *roomFixture) lookalike(tb testing.TB, i int) *e2e.RoomMember {
	tb.Helper()
	want, err := e2e.AuraOf(fx.members[i].Public)
	if err != nil {
		tb.Fatalf("AuraOf: %v", err)
	}
	for try := 0; try < maxGrindTries; try++ {
		member := fx.madeUpMember(tb)
		aura, err := e2e.AuraOf(member.Public)
		if err == nil && aura.Name == want.Name && aura.Code != want.Code {
			return member
		}
	}
	tb.Fatal("no lookalike key found within the bound")
	return nil
}

// madeUpMember is a member key of the fixture's room from a random root: one a member could send
// under, of its own making.
func (fx *roomFixture) madeUpMember(tb testing.TB) *e2e.RoomMember {
	tb.Helper()
	root, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
	if err != nil {
		tb.Fatalf("RandomBytes: %v", err)
	}
	member, err := fx.keys.Member(root)
	if err != nil {
		tb.Fatalf("Member: %v", err)
	}
	return member
}

// sealFrom seals text as from, wrapped for every card in roster (from's own card included).
func (fx *roomFixture) sealFrom(tb testing.TB, from *e2e.RoomMember, roster []string, seq, counter int64, text string) models.MessageDTO {
	tb.Helper()
	recipients, digest, err := fx.keys.Recipients(from, roster)
	if err != nil {
		tb.Fatalf("Recipients: %v", err)
	}
	id := uuid.New()
	blob, err := fx.keys.SealMessage(from, id, recipients, digest, text, fuzzSentAtMillis, counter)
	if err != nil {
		tb.Fatalf("SealMessage: %v", err)
	}
	return models.MessageDTO{ID: id.String(), Seq: seq, Ciphertext: blob}
}

func TestSenders_AreNamedWithCodeLeftAndSameName(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	rows := fx.honestRows()[:2] // this agent and member 1; member 2 is not on the list
	if err := st.verifyMembers(rows); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	impostor := fx.lookalike(t, 1)
	everyone := []string{fx.members[0].Card, fx.members[1].Card, fx.members[2].Card, impostor.Card}
	page := []models.MessageDTO{
		fx.sealFrom(t, fx.members[1], everyone, 1, 1, "genuine"),
		fx.sealFrom(t, impostor, everyone, 2, 1, "lookalike"),
		fx.sealFrom(t, fx.members[2], everyone, 3, 1, "gone"),
	}
	got := st.openPage(page, st.forwardWindow(0, st.forwardLedger()))
	result := newReadResult(st, got.messages, got.gaps, got.replays, got.last)
	if len(result.Messages) != len(page) {
		t.Fatalf("%d messages", len(result.Messages))
	}
	genuine, lookalike, gone := result.Messages[0], result.Messages[1], result.Messages[2]
	wantGenuine, _ := e2e.AuraOf(fx.members[1].Public)
	wantLookalike, _ := e2e.AuraOf(impostor.Public)
	if genuine.Sender != wantGenuine.Name || genuine.SenderCode != wantGenuine.Code || genuine.Left || !genuine.SameName {
		t.Fatalf("the genuine member's message: %+v", genuine.From)
	}
	if lookalike.Sender != genuine.Sender || lookalike.SenderCode != wantLookalike.Code || !lookalike.Left || !lookalike.SameName {
		t.Fatalf("the lookalike's message: %+v", lookalike.From)
	}
	if !gone.Left {
		t.Fatalf("a sender off the member list: %+v", gone.From)
	}
	shown, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"sender_code":"` + wantLookalike.Code + `"`, `"left":true`, `"same_name":true`} {
		if !strings.Contains(string(shown), field) {
			t.Fatalf("the read result lacks %s", field)
		}
	}
}

// A name shared with a sender seen earlier in this process stays marked in later reads.
func TestSenders_SameNameRemembersEarlierSenders(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	if err := st.verifyMembers(fx.honestRows()); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	impostor := fx.lookalike(t, 2)
	everyone := []string{fx.members[0].Card, fx.members[1].Card, fx.members[2].Card, impostor.Card}
	first := st.openPage([]models.MessageDTO{fx.sealFrom(t, impostor, everyone, 1, 1, "earlier")}, st.forwardWindow(0, st.forwardLedger()))
	newReadResult(st, first.messages, first.gaps, first.replays, first.last)
	later := st.openPage([]models.MessageDTO{fx.sealFrom(t, fx.members[2], everyone, 2, 1, "later")}, st.forwardWindow(1, st.forwardLedger()))
	result := newReadResult(st, later.messages, later.gaps, later.replays, later.last)
	if len(result.Messages) != 1 || !result.Messages[0].SameName || result.Messages[0].Left {
		t.Fatalf("the genuine member after a lookalike: %+v", result.Messages)
	}
}
