package agent

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
// A gap is a counter more than one above the sender's last. A history page (before) is judged
// on its own: gaps inside the page only, and it never changes the record.

// counterRecord is what the agent remembers of one room (persisted in the state file).
type counterRecord struct {
	Seq     int64            `json:"seq"`     // highest seq processed by a forward read
	Mine    int64            `json:"mine"`    // highest counter this account spent or was seen to send
	Senders map[string]int64 `json:"senders"` // member public key (base64url) → highest counter
}

func newCounterRecord() *counterRecord {
	return &counterRecord{Senders: make(map[string]int64)}
}

// verdict is judge's decision on one message.
type verdict struct {
	replay bool
	gap    int64
}

// ledger is one loaded sequence judged against record (which it never changes itself).
type ledger struct {
	record  *counterRecord
	run     map[string]int64
	history bool
}

func newLedger(record *counterRecord, history bool) *ledger {
	return &ledger{record: record, run: make(map[string]int64), history: history}
}

// judge is counters.js judge.
func (l *ledger) judge(sender string, counter, seq int64) verdict {
	run, inRun := l.run[sender]
	isNew := seq > l.record.Seq
	stored := l.record.Senders[sender]
	if (inRun && counter <= run) || (isNew && counter <= stored) {
		return verdict{replay: true}
	}
	last := int64(0)
	switch {
	case inRun:
		last = run
	case isNew && !l.history:
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
	if _, known := l.run[sender]; known || len(l.run) < maxTrackedSenders {
		l.run[sender] = counter
	}
}

// snapshot is counters.js snapshot: record raised by this sequence, processed up to seq. A
// history ledger changes nothing. It reports whether the record changed.
func (l *ledger) snapshot(record *counterRecord, seq int64) bool {
	if l.history {
		return false
	}
	changed := false
	if seq > record.Seq {
		record.Seq, changed = seq, true
	}
	for sender, counter := range l.run {
		last, known := record.Senders[sender]
		if counter > last && (known || len(record.Senders) < maxTrackedSenders) {
			record.Senders[sender], changed = counter, true
		}
	}
	return changed
}

// raiseMine records a counter of this account's; it reports whether the record changed.
func (r *counterRecord) raiseMine(counter int64) bool {
	if counter <= r.Mine {
		return false
	}
	r.Mine = counter
	return true
}
