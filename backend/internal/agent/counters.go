package agent

import "slices"

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
// its record's array): the sender bound displaces the off-roster entry recorded longest ago.
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
//   - a new kept sender is always recorded: it displaces the entry recorded longest ago that is
//     not kept; this agent's own entry and the roster's are never displaced.

// recordSender records a new sender at counter under the bound; it reports whether it did.
func (r *counterRecord) recordSender(sender string, counter int64, kept func(string) bool) bool {
	if len(r.Senders) >= maxTrackedSenders {
		if !kept(sender) {
			return false
		}
		for i, victim := range r.Order {
			if !kept(victim) {
				delete(r.Senders, victim)
				r.Order = slices.Delete(r.Order, i, i+1)
				break
			}
		}
	}
	r.Senders[sender] = counter
	r.Order = append(r.Order, sender)
	return true
}

// verdict is judge's decision on one message.
type verdict struct {
	replay bool
	gap    int64
}

// ledger is one loaded sequence judged against record (which it never changes itself). ceiling
// is nil for a forward sequence; for an earlier page it holds each sender's lowest counter known
// above the page, and is never nil (an empty ceiling still marks a history ledger).
type ledger struct {
	record   *counterRecord
	run      map[string]int64
	runOrder []string // the keys of run, first admitted first: new senders are recorded in this order
	ceiling  map[string]int64
}

// newLedger is counters.js ledger: a forward sequence.
func newLedger(record *counterRecord) *ledger {
	return &ledger{record: record, run: make(map[string]int64)}
}

// newHistoryLedger is counters.js history: an earlier page under its ceiling.
func newHistoryLedger(record *counterRecord, ceiling map[string]int64) *ledger {
	if ceiling == nil {
		ceiling = make(map[string]int64)
	}
	return &ledger{record: record, run: make(map[string]int64), ceiling: ceiling}
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

// admit is counters.js admit: a message judge did not call a replay. Senders beyond the bound
// are not tracked (a room has at most 32 seats at a time).
func (l *ledger) admit(sender string, counter int64) {
	_, known := l.run[sender]
	if !known && len(l.run) >= maxTrackedSenders {
		return
	}
	if !known {
		l.runOrder = append(l.runOrder, sender)
	}
	l.run[sender] = counter
}

// snapshot is counters.js snapshot and bound: record raised by this sequence, processed up to
// seq, new senders recorded in the order first admitted under THE SENDER BOUND (kept says which
// keys the bound never refuses nor displaces). A history ledger changes nothing. It reports
// whether the record changed, and the senders the bound did not record.
func (l *ledger) snapshot(record *counterRecord, seq int64, kept func(string) bool) (bool, []string) {
	if l.history() {
		return false, nil
	}
	changed := false
	if seq > record.Seq {
		record.Seq, changed = seq, true
	}
	var refused []string
	for _, sender := range l.runOrder {
		counter := l.run[sender]
		last, known := record.Senders[sender]
		switch {
		case known && counter > last:
			record.Senders[sender], changed = counter, true
		case known:
		case record.recordSender(sender, counter, kept):
			changed = true
		default:
			refused = append(refused, sender)
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
