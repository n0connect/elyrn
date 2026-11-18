package agent

import (
	"slices"
	"testing"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
)

// THE SENDER BOUND, as counters.js bound: at the bound a new sender off the current roster is not
// recorded (its messages say unrecorded), a new roster member always is and displaces the
// off-roster entry recorded most recently (marked unrecorded), and this agent's own entry and the
// roster's are never displaced. The old rule recorded nobody new at the bound, roster members included, and said
// nothing.

// madeUpSender is a sender key of nobody's: what a member sending under keys of its own making
// shows.
func madeUpSender(t *testing.T) string {
	t.Helper()
	key, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	return senderKey(key)
}

// fullRecord fills st's record to the bound: this agent's own key first, then made-up senders.
func fullRecord(t *testing.T, st *roomState) []string {
	t.Helper()
	own := senderKey(st.member.Public)
	st.counters.recordSender(own, 1, st.keptSender)
	var madeUp []string
	for len(st.counters.Senders) < maxTrackedSenders {
		sender := madeUpSender(t)
		if recorded, _ := st.counters.recordSender(sender, 1, st.keptSender); recorded {
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
	l := st.forwardLedger()
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
	newest := madeUp[len(madeUp)-1]
	if _, kept := st.counters.Senders[newest]; kept {
		t.Fatal("the off-roster entry recorded most recently was not the one displaced")
	}
	if _, kept := st.counters.Senders[madeUp[0]]; !kept {
		t.Fatal("the off-roster entry recorded longest ago was displaced")
	}
	if _, marked := st.unrecorded[newest]; !marked {
		t.Fatal("the displaced sender is not marked unrecorded")
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
		st.counters.recordSender(madeUpSender(t), 1, kept)
	}
	before := len(st.counters.Senders)
	if recorded, displaced := st.counters.recordSender(senderKey(fx.members[1].Public), 1, kept); !recorded || displaced != "" ||
		len(st.counters.Senders) != before+1 {
		t.Fatal("a kept sender was refused, or displaced another kept one")
	}
}

// A flood of made-up senders early in one loaded sequence must not stop a roster member from being
// tracked: rule 1 still applies to it and its record is raised, while a made-up sender arriving at
// the bound is reported with the refused senders, once. Before, the run refused every new sender
// at the bound, roster members included, and said nothing.
func TestSenderBound_AFloodNeverUntracksARosterMember(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	if err := st.verifyMembers(fx.honestRows()); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	l := st.forwardLedger()
	for range maxTrackedSenders {
		l.admit(madeUpSender(t), 1)
	}
	member, late := senderKey(fx.members[1].Public), madeUpSender(t)
	l.admit(member, 5)
	l.admit(late, 1)
	l.admit(late, 2)
	seq := int64(maxTrackedSenders + 3)
	if !l.judge(member, 5, seq).replay {
		t.Fatal("rule 1 did not apply to a roster member that arrived after the flood")
	}
	_, refused := l.snapshot(st.counters, seq)
	if st.counters.Senders[member] != 5 {
		t.Fatalf("the roster member's record is %d, want 5", st.counters.Senders[member])
	}
	if slices.Contains(refused, member) {
		t.Fatal("the roster member was refused")
	}
	if n := len(slices.DeleteFunc(slices.Clone(refused), func(key string) bool { return key != late })); n != 1 {
		t.Fatalf("the made-up sender the run did not track is reported %d times, want once", n)
	}
}

// The bounded unrecorded set never fails open: once a refused sender finds it full, every sender
// neither kept nor recorded is marked unrecorded, until the record takes enough of the set to
// leave it room again. Before, the dropped sender's messages showed as recorded.
func TestSenderBound_AFullUnrecordedSetFailsClosed(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	if err := st.verifyMembers(fx.honestRows()[:2]); err != nil { // member 2 is off the roster
		t.Fatalf("verifyMembers: %v", err)
	}
	var noted []string
	for range maxUnrecordedSenders {
		noted = append(noted, madeUpSender(t))
	}
	st.noteUnrecorded(noted)
	dropped := madeUpSender(t)
	st.noteUnrecorded([]string{dropped})
	if _, kept := st.unrecorded[dropped]; kept || !st.unrecordedSender(dropped) {
		t.Fatal("a sender the full set could not note shows as recorded")
	}
	member := senderKey(fx.members[1].Public)
	if st.unrecordedSender(member) || st.unrecordedSender(senderKey(st.member.Public)) {
		t.Fatal("a kept sender is marked unrecorded")
	}
	everyone := []string{fx.members[0].Card, fx.members[1].Card, fx.members[2].Card}
	page := []models.MessageDTO{fx.sealFrom(t, fx.members[2], everyone, 1, 1, "off the roster, never recorded")}
	got := st.openPage(page, st.forwardWindow(0, st.forwardLedger()))
	result := newReadResult(st, got.messages, got.gaps, got.replays, got.last)
	if len(result.Messages) != 1 || !result.Messages[0].Unrecorded {
		t.Fatalf("a sender neither kept nor recorded, while the set was full: %+v", result.Messages)
	}
	st.counters.Senders[noted[0]] = 1 // the record took one: the set has room again
	st.noteUnrecorded(nil)
	if st.unrecordedSender(madeUpSender(t)) {
		t.Fatal("the overflow mark outlived the room the record made in the set")
	}
}
