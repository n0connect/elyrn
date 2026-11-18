package agent

import (
	"maps"
	"slices"
)

// Replay, reorder and gap detection per sender: frontend/js/counters.js, rule for rule. Every
// message carries its sender's counter inside the authenticated payload, so the server can
// withhold, repeat or reorder messages but never change a counter. For one sender the counter
// grows strictly with seq, so:
//  1. within one loaded sequence (one read, or one counter sync), a sender's counter must be
//     strictly above the last one seen from them;
//  2. across reads and restarts, the record remembers the highest seq processed and each
//     sender's highest counter at that point: a message above that seq must carry a counter
//     above the sender's remembered one. At or below it, the message is history already seen
//     and only rule 1 applies, so reading the same page again is not a replay.
// A gap is a counter more than one above the sender's last.
//
// Earlier pages (before), as counters.js EARLIER PAGES: each page is judged on its own ledger
// (newHistoryLedger, counters.js history): rule 1 inside the page, rule 2 against the record,
// and each sender's counter must stay below the lowest one already known for that sender above
// the page (its ceiling: roomState.ceilingAbove, counters.js lowest); at or above it is a replay
// or a reorder. A gap is measured inside the page only, and a history ledger never changes the
// record.

// counterRecord is what the agent remembers of one room (persisted in the state file). Expires is
// the room's own expiry (unix seconds) from its verified code: the only fact a record is pruned
// on (state.go); 0 in a record written before it was kept.
//
// Order lists the keys of Senders in the order they were first recorded (counters.js keeps it in
// its record's array): the sender bound displaces the off-roster entry recorded most recently.
type counterRecord struct {
	Seq     int64            `json:"seq"`               // highest seq processed by a forward read
	Mine    int64            `json:"mine"`              // highest counter this account spent or was seen to send
	Senders map[string]int64 `json:"senders"`           // member public key (base64url) → highest counter
	Order   []string         `json:"order,omitempty"`   // the keys of Senders, first recorded first
	Expires int64            `json:"expires,omitempty"` // the room's expiry from its code, unix seconds
}

func newCounterRecord() *counterRecord {
	return &counterRecord{Senders: make(map[string]int64)}
}

// THE SENDER BOUND (counters.js bound). A record names at most maxTrackedSenders senders. A room
// member could send under keys of its own making, so the senders a record sees are not bounded by
// its seats; an entry recorded earlier is never given up to a made-up sender:
//   - a new sender that is not kept (kept: this agent's own key and the current roster) is recorded
//     only while there is room; at the bound it is not recorded (its messages say unrecorded);
//   - a new kept sender is always recorded: a new kept sender displaces the off-roster entry
//     recorded most recently; the displaced sender is marked unrecorded. A long-held entry is a
//     real former member, while a flood of made-up keys is recorded later, so the flood gives way
//     first (the direction counters.js trim takes). This agent's own entry and the roster's are
//     never displaced.

// recordSender records a new sender at counter under the bound; it reports whether it did, and
// the sender it displaced ("" when none), which the caller reports like a refused one.
func (r *counterRecord) recordSender(sender string, counter int64, kept func(string) bool) (bool, string) {
	displaced := ""
	if len(r.Senders) >= maxTrackedSenders {
		if !kept(sender) {
			return false, ""
		}
		for i := len(r.Order) - 1; i >= 0; i-- {
			if victim := r.Order[i]; !kept(victim) {
				delete(r.Senders, victim)
				r.Order = slices.Delete(r.Order, i, i+1)
				displaced = victim
				break
			}
		}
	}
	r.Senders[sender] = counter
	r.Order = append(r.Order, sender)
	return true, displaced
}

// verdict is judge's decision on one message.
type verdict struct {
	replay bool
	gap    int64
}

// ledger is one loaded sequence judged against record (which it never changes itself). ceiling
// is nil for a forward sequence; for an earlier page it holds each sender's lowest counter known
// above the page, and is never nil (an empty ceiling still marks a history ledger). kept is the
// sender bound's keep set (roomState.keptSender), learnt where the ledger is built: the one home
// of the bound for the run as for the record.
type ledger struct {
	record    *counterRecord
	kept      func(string) bool
	run       map[string]int64
	runOrder  []string            // the keys of run, first admitted first: new senders are recorded in this order
	untracked []string            // senders the run did not track (THE SENDER BOUND), first seen first, each once
	refusedIn map[string]struct{} // the keys of untracked
	ceiling   map[string]int64
}

// newLedger is counters.js ledger: a forward sequence.
func newLedger(record *counterRecord, kept func(string) bool) *ledger {
	return &ledger{record: record, kept: kept, run: make(map[string]int64), refusedIn: make(map[string]struct{})}
}

// newHistoryLedger is counters.js history: an earlier page under its ceiling.
func newHistoryLedger(record *counterRecord, ceiling map[string]int64, kept func(string) bool) *ledger {
	if ceiling == nil {
		ceiling = make(map[string]int64)
	}
	l := newLedger(record, kept)
	l.ceiling = ceiling
	return l
}

func (l *ledger) history() bool { return l.ceiling != nil }

// judge is counters.js judge, its ceiling clause included.
func (l *ledger) judge(sender string, counter, seq int64) verdict {
	run, inRun := l.run[sender]
	isNew := seq > l.record.Seq
	stored := l.record.Senders[sender]
	ceiling, capped := l.ceiling[sender]
	if (inRun && counter <= run) || (isNew && counter <= stored) || (capped && counter >= ceiling) {
		return verdict{replay: true}
	}
	// An earlier page measures gaps from inside itself only (counters.js EARLIER PAGES)
	last := int64(0)
	switch {
	case inRun:
		last = run
	case isNew && !l.history():
		last = stored
	}
	if last > 0 && counter > last+1 {
		return verdict{gap: counter - last - 1}
	}
	return verdict{}
}

// admit is counters.js admit: a message judge did not call a replay. The run tracks senders under
// THE SENDER BOUND: a kept sender is always tracked (so the run exceeds the bound by at most the
// kept set), and a sender that is not kept and arrives at the bound is not: rule 1 no longer
// applies to it, so snapshot reports it with the senders the record refused (its messages say
// unrecorded). A flood of made-up senders can thus never keep a roster member untracked.
func (l *ledger) admit(sender string, counter int64) {
	if _, known := l.run[sender]; !known {
		if len(l.run) >= maxTrackedSenders && !l.kept(sender) {
			if _, noted := l.refusedIn[sender]; !noted {
				l.refusedIn[sender] = struct{}{}
				l.untracked = append(l.untracked, sender)
			}
			return
		}
		l.runOrder = append(l.runOrder, sender)
	}
	l.run[sender] = counter
}

// snapshot is counters.js snapshot and bound: record raised by this sequence, processed up to
// seq, new senders recorded in the order first admitted under THE SENDER BOUND (the ledger's kept
// says which keys the bound never refuses nor displaces). A history ledger changes nothing. It
// reports whether the record changed, and the refused senders, each once: those the run did not
// track, then those the record did not take or gave up to a kept sender (displaced).
func (l *ledger) snapshot(record *counterRecord, seq int64) (bool, []string) {
	if l.history() {
		return false, nil
	}
	changed := false
	if seq > record.Seq {
		record.Seq, changed = seq, true
	}
	refused, listed := slices.Clone(l.untracked), maps.Clone(l.refusedIn)
	refuse := func(key string) {
		if _, done := listed[key]; !done {
			listed[key] = struct{}{}
			refused = append(refused, key)
		}
	}
	for _, sender := range l.runOrder {
		counter := l.run[sender]
		last, known := record.Senders[sender]
		if known {
			if counter > last {
				record.Senders[sender], changed = counter, true
			}
			continue
		}
		recorded, displaced := record.recordSender(sender, counter, l.kept)
		switch {
		case !recorded:
			refuse(sender)
		case displaced != "":
			refuse(displaced)
			changed = true
		default:
			changed = true
		}
	}
	return changed, refused
}

// raiseMine records a counter of this account's; it reports whether the record changed.
func (r *counterRecord) raiseMine(counter int64) bool {
	if counter <= r.Mine {
		return false
	}
	r.Mine = counter
	return true
}
