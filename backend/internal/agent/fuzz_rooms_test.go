package agent

import (
	"fmt"
	"strings"
	"testing"

	"elyrn/internal/e2e"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Room pages served by a hostile server: real messages of a real three-member room, sealed once,
// served in any order, at any position, repeated, re-sealed under a new id by their sender,
// mutated, or with a false "mine" flag. The fuzzer drives a sequence of forward reads and
// history pages through the agent's own openPage and ledger and checks the replay judgement
// (counters.go) against an independent model of what was delivered.
// Run with: go test -tags test -run '^$' -fuzz '^FuzzRoomPages$' -fuzztime 60s ./internal/agent

const (
	fuzzMembers      = 3 // this agent (fuzzSelf) and two others
	fuzzSelf         = 0
	fuzzCounters     = 6 // counters 1..fuzzCounters per sender
	fuzzResealEvery  = 2 // every such counter is sealed twice, under two ids (a member's replay)
	fuzzSeqSpan      = 64
	fuzzMaxPage      = 8
	fuzzMaxPages     = 32
	fuzzItemBytes    = 3
	fuzzSentAtMillis = 1767225600000
	// Each message's text names its pool entry and ends with characters the agent must
	// neutralise (D7): a bidi override and a bell.
	fuzzTextFormat  = "p%02d"
	fuzzHostileTail = "\u202e\u0007"
	// Mutations of a served blob: the body's tag is changed, cut, extended, or another
	// message's blob is served under this id. bodyTailChars lands inside the body's tag.
	fuzzBodyTailChars = 8
	fuzzCutChars      = 4
	fuzzExtraChars    = "AAAA"
)

// mutation is what the server did to one served message.
type mutation int

const (
	served mutation = iota // three genuine kinds out of eight, so most messages are honest
	servedAgain
	servedOnceMore
	wrongMine
	flippedBody
	cutBlob
	extendedBlob
	swappedBlob
	mutationKinds
)

func (m mutation) genuine() bool { return m <= servedOnceMore }

type poolEntry struct {
	id      uuid.UUID
	sender  int
	counter int64
	blob    string
	text    string // as the agent must show it: neutralised
}

// roomFixture is one room, its members and every message the fuzzer may serve.
type roomFixture struct {
	keys    *e2e.Room
	members []*e2e.RoomMember
	pool    []poolEntry
	byID    map[uuid.UUID]int
}

func newRoomFixture(tb testing.TB) *roomFixture {
	tb.Helper()
	code, err := e2e.NewRoomCode(fuzzMembers, 1)
	if err != nil {
		tb.Fatalf("NewRoomCode: %v", err)
	}
	keys, err := e2e.DeriveRoom(code.Secret)
	if err != nil {
		tb.Fatalf("DeriveRoom: %v", err)
	}
	fx := &roomFixture{keys: keys, byID: make(map[uuid.UUID]int)}
	roster := make([]string, 0, fuzzMembers)
	for range fuzzMembers {
		number, err := utils.GenerateAccountNumber()
		if err != nil {
			tb.Fatalf("GenerateAccountNumber: %v", err)
		}
		root, err := e2e.RoomsRoot(number)
		if err != nil {
			tb.Fatalf("RoomsRoot: %v", err)
		}
		member, err := keys.Member(root)
		if err != nil {
			tb.Fatalf("Member: %v", err)
		}
		fx.members = append(fx.members, member)
		roster = append(roster, member.Card)
	}
	for sender := range fuzzMembers {
		for counter := int64(1); counter <= fuzzCounters; counter++ {
			fx.seal(tb, roster, sender, counter)
			if counter%fuzzResealEvery == 0 {
				fx.seal(tb, roster, sender, counter)
			}
		}
	}
	return fx
}

func (fx *roomFixture) seal(tb testing.TB, roster []string, sender int, counter int64) {
	tb.Helper()
	index := len(fx.pool)
	label := fmt.Sprintf(fuzzTextFormat, index)
	me := fx.members[sender]
	recipients, digest, err := fx.keys.Recipients(me, roster)
	if err != nil {
		tb.Fatalf("Recipients: %v", err)
	}
	id := uuid.New()
	blob, err := fx.keys.SealMessage(me, id, recipients, digest, label+fuzzHostileTail, fuzzSentAtMillis, counter)
	if err != nil {
		tb.Fatalf("SealMessage: %v", err)
	}
	shown := label + strings.Repeat(string(replacementRune), len([]rune(fuzzHostileTail)))
	fx.pool = append(fx.pool, poolEntry{id: id, sender: sender, counter: counter, blob: blob, text: shown})
	fx.byID[id] = index
}

// state is the room as this agent holds it after a fresh start: nothing seen, nothing recorded.
func (fx *roomFixture) state() *roomState {
	return &roomState{id: fx.keys.ID, keys: fx.keys, member: fx.members[fuzzSelf],
		counters: newCounterRecord(), seen: make(map[uuid.UUID]seenMessage)}
}

// servedItem is one message of a served page.
type servedItem struct {
	entry int
	seq   int64
	how   mutation
}

func (fx *roomFixture) dto(item servedItem) models.MessageDTO {
	e := fx.pool[item.entry]
	blob, mine := e.blob, e.sender == fuzzSelf
	switch item.how {
	case wrongMine:
		mine = !mine
	case flippedBody:
		b := []byte(blob)
		at := len(b) - fuzzBodyTailChars
		if b[at] == 'A' {
			b[at] = 'B'
		} else {
			b[at] = 'A'
		}
		blob = string(b)
	case cutBlob:
		blob = blob[:len(blob)-fuzzCutChars]
	case extendedBlob:
		blob += fuzzExtraChars
	case swappedBlob:
		blob = fx.pool[(item.entry+1)%len(fx.pool)].blob
	}
	return models.MessageDTO{ID: e.id.String(), Seq: item.seq, Mine: mine, Ciphertext: blob}
}

// pageHarness is the independent model: what was delivered where, and what was a replay.
type pageHarness struct {
	t        *testing.T
	fx       *roomFixture
	st       *roomState
	firstSeq map[uuid.UUID]int64 // the seq each delivered id was first delivered at
	replayed map[uuid.UUID]bool  // ids reported as a replay at least once
	lastNew  map[int]int64       // per sender, the counter of the last message delivered as new
}

// accepted replays openPage's shape filter (served ids are canonical and blobs bounded): the
// items it judges, by seq.
func (h *pageHarness) accepted(items []servedItem, after, before int64) map[int64]servedItem {
	out := make(map[int64]servedItem)
	inPage := make(map[uuid.UUID]bool)
	last := after
	for _, item := range items {
		id := h.fx.pool[item.entry].id
		if inPage[id] || item.seq <= last || (before > 0 && item.seq >= before) {
			continue
		}
		inPage[id] = true
		last = item.seq
		out[item.seq] = item
	}
	return out
}

// ceiling is the model's lowest counter per sender among the ids delivered at or above before
// and never reported as a replay. The agent's own ceiling (ceilingAbove) may be lower, never
// higher, so a history page must stay under this one.
func (h *pageHarness) ceiling(before int64) map[int]int64 {
	out := make(map[int]int64)
	for id, seq := range h.firstSeq {
		if h.replayed[id] || seq < before {
			continue
		}
		e := h.fx.pool[h.fx.byID[id]]
		if lowest, known := out[e.sender]; !known || e.counter < lowest {
			out[e.sender] = e.counter
		}
	}
	return out
}

func (h *pageHarness) dtos(items []servedItem) []models.MessageDTO {
	out := make([]models.MessageDTO, 0, len(items))
	for _, item := range items {
		out = append(out, h.fx.dto(item))
	}
	return out
}

// forward is one read after `after`, as Agent.read does it (without the network).
func (h *pageHarness) forward(items []servedItem, after int64) {
	st := h.st
	recordSeq := st.counters.Seq
	accepted := h.accepted(items, after, 0)
	l := st.forwardLedger()
	got := st.openPage(h.dtos(items), st.forwardWindow(after, l))
	st.settle(l, got.last)
	h.check(got, accepted, func(e poolEntry, seq int64) {
		if seq <= recordSeq {
			return
		}
		if e.counter <= h.lastNew[e.sender] {
			h.t.Fatalf("sender %d counter %d delivered as new at seq %d after counter %d", e.sender, e.counter, seq, h.lastNew[e.sender])
		}
		h.lastNew[e.sender] = e.counter
	})
	wantLast := after
	for seq := range accepted {
		wantLast = max(wantLast, seq)
	}
	if got.last != wantLast || st.counters.Seq != max(recordSeq, wantLast) {
		h.t.Fatalf("read after %d: last %d (want %d), record seq %d", after, got.last, wantLast, st.counters.Seq)
	}
}

// history is one page below before (Agent.ReadBefore): it never changes the record but this
// account's own counter, which only rises.
func (h *pageHarness) history(items []servedItem, before int64) {
	st := h.st
	recordSeq, mine := st.counters.Seq, st.counters.Mine
	senders := make(map[string]int64, len(st.counters.Senders))
	for k, v := range st.counters.Senders {
		senders[k] = v
	}
	ceiling := h.ceiling(before)
	accepted := h.accepted(items, 0, before)
	got := st.openPage(h.dtos(items), st.historyWindow(before))
	h.check(got, accepted, func(e poolEntry, seq int64) {
		if seq >= before {
			h.t.Fatalf("history below %d delivered seq %d", before, seq)
		}
		if lowest, capped := ceiling[e.sender]; capped && e.counter >= lowest {
			h.t.Fatalf("history below %d delivered sender %d counter %d at or above its ceiling %d", before, e.sender, e.counter, lowest)
		}
	})
	if st.counters.Seq != recordSeq || st.counters.Mine < mine || len(st.counters.Senders) != len(senders) {
		h.t.Fatal("a history page changed the room's record")
	}
	for k, v := range senders {
		if st.counters.Senders[k] != v {
			h.t.Fatal("a history page changed a sender's counter")
		}
	}
}

// check holds for every page: every judged item is answered once; a mutated message is never
// opened; a genuine one is shown neutralised and never broken; per sender, delivered counters
// rise strictly (rule 1); an id is delivered at one seq only; this account's counter is never
// below one of its messages served. delivered runs the window's own rule on each delivery.
func (h *pageHarness) check(got *opened, accepted map[int64]servedItem, delivered func(poolEntry, int64)) {
	t := h.t
	if len(got.messages)+len(got.replays) != len(accepted) {
		t.Fatalf("%d messages and %d replays for %d judged items", len(got.messages), len(got.replays), len(accepted))
	}
	lastCounter := make(map[int]int64)
	for _, m := range got.messages {
		item, ok := accepted[m.Seq]
		if !ok {
			t.Fatalf("seq %d delivered but never judged", m.Seq)
		}
		e := h.fx.pool[item.entry]
		if !item.how.genuine() {
			if !m.Broken || m.Text != "" || m.Sender != "" {
				t.Fatalf("a mutated message (%d) at seq %d was opened", item.how, m.Seq)
			}
			continue
		}
		if m.Broken || m.Text != e.text || m.Mine != (e.sender == fuzzSelf) || strings.IndexFunc(m.Text, forbiddenRune) >= 0 {
			t.Fatalf("the genuine message at seq %d was shown as %+v", m.Seq, m)
		}
		if last, ok := lastCounter[e.sender]; ok && e.counter <= last {
			t.Fatalf("sender %d counter %d delivered after %d in one page", e.sender, e.counter, last)
		}
		lastCounter[e.sender] = e.counter
		if first, ok := h.firstSeq[e.id]; ok && first != m.Seq {
			t.Fatalf("one message delivered at seq %d and at seq %d", first, m.Seq)
		}
		h.firstSeq[e.id] = m.Seq
		delivered(e, m.Seq)
	}
	for _, r := range got.replays {
		item, ok := accepted[r.Seq]
		if !ok || !item.how.genuine() {
			t.Fatalf("seq %d reported as a replay but not a judged genuine message", r.Seq)
		}
		h.replayed[h.fx.pool[item.entry].id] = true
	}
	for _, g := range got.gaps {
		if g.Missing < 1 {
			t.Fatalf("a gap of %d", g.Missing)
		}
	}
	for _, item := range accepted {
		if e := h.fx.pool[item.entry]; item.how.genuine() && e.sender == fuzzSelf && h.st.counters.Mine < e.counter {
			t.Fatalf("this account's counter %d is below its served counter %d", h.st.counters.Mine, e.counter)
		}
	}
}

// fuzzReader hands out the fuzzer's bytes; at the end it reports false.
type fuzzReader struct {
	data []byte
	at   int
}

func (r *fuzzReader) next() (byte, bool) {
	if r.at >= len(r.data) {
		return 0, false
	}
	r.at++
	return r.data[r.at-1], true
}

// page decodes one page: kind (bit 0: history), window, count, then per item entry, seq, how.
func (r *fuzzReader) page(pool int) (history bool, window int64, items []servedItem, ok bool) {
	kind, ok1 := r.next()
	at, ok2 := r.next()
	count, ok3 := r.next()
	if !ok1 || !ok2 || !ok3 {
		return false, 0, nil, false
	}
	for range int(count) % (fuzzMaxPage + 1) {
		if r.at+fuzzItemBytes > len(r.data) {
			break
		}
		entry, _ := r.next()
		seq, _ := r.next()
		how, _ := r.next()
		items = append(items, servedItem{entry: int(entry) % pool, seq: int64(seq) % fuzzSeqSpan, how: mutation(how) % mutationKinds})
	}
	return kind&1 == 1, int64(at) % fuzzSeqSpan, items, true
}

// pageSeed encodes pages for the corpus: each is kind, window, then (entry, seq, how) items.
func pageSeed(pages ...[]byte) []byte {
	var out []byte
	for _, p := range pages {
		out = append(out, p[0], p[1], byte((len(p)-2)/fuzzItemBytes))
		out = append(out, p[2:]...)
	}
	return out
}

func FuzzRoomPages(f *testing.F) {
	fx := newRoomFixture(f)
	other := byte(fuzzCounters + fuzzCounters/fuzzResealEvery) // first entry of the second member
	f.Add(pageSeed(
		[]byte{0, 0, 0, 1, 0, other, 2, 0, 1, 3, 0},    // forward: three honest messages
		[]byte{0, 0, 0, 1, 0, other, 2, 0, 1, 3, 0},    // the same page again: history, not a replay
		[]byte{0, 3, other + 2, 4, 0, other, 5, 0},     // a lower counter after a higher one: a replay
		[]byte{1, 3, 0, 1, 0, other + 1, 2, 0},         // history below 4, one counter at its ceiling
		[]byte{0, 5, 3, 6, byte(flippedBody), 4, 7, 0}, // a mutated body, then a gap
		[]byte{0, 7, 5, 8, byte(wrongMine), 6, 9, byte(swappedBlob)},
	))
	f.Add(pageSeed(
		[]byte{0, 0, 2, 10, 0}, // this account's counter 2 (second id)
		[]byte{0, 0, 1, 11, 0}, // counter 2 again under its first id, as new: a replay
		[]byte{1, 9, 0, 5, 0},  // history below 10: counter 1 under the ceiling 2
		[]byte{1, 9, 3, 6, 0},  // history below 10: counter 3 above the ceiling 2, a replay
		[]byte{0, 11, 6, 12, byte(cutBlob), 7, 13, byte(extendedBlob)},
	))
	f.Fuzz(func(t *testing.T, ops []byte) {
		h := &pageHarness{t: t, fx: fx, st: fx.state(), firstSeq: make(map[uuid.UUID]int64),
			replayed: make(map[uuid.UUID]bool), lastNew: make(map[int]int64)}
		r := &fuzzReader{data: ops}
		for range fuzzMaxPages {
			history, window, items, ok := r.page(len(fx.pool))
			if !ok {
				return
			}
			if history {
				h.history(items, window+1)
			} else {
				h.forward(items, window)
			}
		}
	})
}

// FuzzOpenServedMessage serves arbitrary ciphertext under a real message id: it opens only to
// that message's own text, sender and "mine", and otherwise is broken with no text.
func FuzzOpenServedMessage(f *testing.F) {
	fx := newRoomFixture(f)
	for i, e := range fx.pool[:fuzzCounters+1] {
		f.Add(uint8(i), e.blob, e.sender == fuzzSelf)
		f.Add(uint8(i), e.blob[:len(e.blob)/2], e.sender == fuzzSelf)
	}
	f.Add(uint8(0), "", true)
	f.Add(uint8(0), fuzzExtraChars, false)
	f.Fuzz(func(t *testing.T, entry uint8, ciphertext string, mine bool) {
		index := int(entry) % len(fx.pool)
		e := fx.pool[index]
		st := fx.state()
		got := st.openPage([]models.MessageDTO{{ID: e.id.String(), Seq: 1, Mine: mine, Ciphertext: ciphertext}},
			st.forwardWindow(0, st.forwardLedger()))
		if len(got.replays) != 0 {
			t.Fatal("the first message of a fresh room was judged a replay")
		}
		for _, m := range got.messages {
			if m.Broken {
				if m.Text != "" || m.Sender != "" {
					t.Fatal("a broken message carries text or a sender")
				}
				continue
			}
			if m.Text != e.text || m.Mine != (e.sender == fuzzSelf) || mine != m.Mine {
				t.Fatalf("ciphertext served under entry %d opened as %+v", index, m)
			}
		}
	})
}
