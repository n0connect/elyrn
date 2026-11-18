package agent

import (
	"testing"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
)

// THE SENDER BOUND, as counters.js bound: at the bound a new sender off the current roster is not
// recorded (its messages say unrecorded), a new roster member always is and displaces the
// off-roster entry recorded longest ago, and this agent's own entry and the roster's are never
// displaced. The old rule recorded nobody new at the bound, roster members included, and said
// nothing.

// fullRecord fills st's record to the bound: this agent's own key first, then made-up senders.
func fullRecord(t *testing.T, st *roomState) []string {
	t.Helper()
	own := senderKey(st.member.Public)
	st.counters.recordSender(own, 1, st.keptSender)
	var madeUp []string
	for len(st.counters.Senders) < maxTrackedSenders {
		key, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
		if err != nil {
			t.Fatalf("RandomBytes: %v", err)
		}
		sender := senderKey(key)
		if st.counters.recordSender(sender, 1, st.keptSender) {
			madeUp = append(madeUp, sender)
		}
	}
	return madeUp
}

func TestSenderBound_KeepsTheRosterRefusesMadeUpSenders(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	if err := st.verifyMembers(fx.honestRows()[:2]); err != nil { // member 2 is off the roster
		t.Fatalf("verifyMembers: %v", err)
	}
	madeUp := fullRecord(t, st)
	everyone := []string{fx.members[0].Card, fx.members[1].Card, fx.members[2].Card}
	page := []models.MessageDTO{
		fx.sealFrom(t, fx.members[2], everyone, 1, 1, "off the roster"),
		fx.sealFrom(t, fx.members[1], everyone, 2, 1, "on the roster"),
	}
	l := newLedger(st.counters)
	got := st.openPage(page, st.forwardWindow(0, l))
	st.settle(l, got.last)
	result := newReadResult(st, got.messages, got.gaps, got.replays, got.last)

	off, on := senderKey(fx.members[2].Public), senderKey(fx.members[1].Public)
	if _, recorded := st.counters.Senders[off]; recorded {
		t.Fatal("a new sender off the roster was recorded in a full record")
	}
	if _, recorded := st.counters.Senders[on]; !recorded {
		t.Fatal("a new roster member was not recorded in a full record")
	}
	if _, kept := st.counters.Senders[madeUp[0]]; kept {
		t.Fatal("the off-roster entry recorded longest ago was not the one displaced")
	}
	if _, kept := st.counters.Senders[senderKey(st.member.Public)]; !kept || len(st.counters.Senders) != maxTrackedSenders {
		t.Fatalf("this agent's own entry gave way, or the bound moved: %d senders", len(st.counters.Senders))
	}
	if len(st.counters.Order) != len(st.counters.Senders) || st.counters.Order[len(st.counters.Order)-1] != on {
		t.Fatal("the order does not list the senders as recorded")
	}
	if len(result.Messages) != 2 || !result.Messages[0].Unrecorded || result.Messages[1].Unrecorded {
		t.Fatalf("unrecorded marks: %+v", result.Messages)
	}
}

// Only roster members and this agent's own key are never displaced: a record full of them alone
// takes one more roster member above the bound rather than give one up.
func TestSenderBound_NeverDisplacesAKeptSender(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	if err := st.verifyMembers(fx.honestRows()); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	kept := func(string) bool { return true }
	for len(st.counters.Senders) < maxTrackedSenders {
		key, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
		if err != nil {
			t.Fatalf("RandomBytes: %v", err)
		}
		st.counters.recordSender(senderKey(key), 1, kept)
	}
	before := len(st.counters.Senders)
	if !st.counters.recordSender(senderKey(fx.members[1].Public), 1, kept) || len(st.counters.Senders) != before+1 {
		t.Fatal("a kept sender was refused, or displaced another kept one")
	}
}
