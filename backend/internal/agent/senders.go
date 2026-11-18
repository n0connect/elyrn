package agent

import (
	"context"
	"encoding/base64"

	"elyrn/internal/e2e"
)

// Senders as the browser shows them (audit F2,
// agent-room-message/sender-reported-by-12bit-name-without-code-or-roster-binding). An aura name
// is 12 bits: a member can grind a key whose name equals a trusted member's and seal a card for
// it. So a sender is named by name and code, and marked left when its key is not on the room's
// current member list, and same_name when another key in view shows the same name (chat.js
// openRoomMessage, which keeps the outsiders it saw for the same comparison).

// currentRoster loads the member list when none is held (the first read of the room in this
// process, or after a "conv" event or a 412 dropped it): left is judged against it.
func (a *Agent) currentRoster(ctx context.Context, st *roomState) error {
	if st.rosterCards != nil {
		return nil
	}
	return a.loadRoster(ctx, st)
}

// attribute marks every sender in r. Keys in view: the current roster, every sender this agent
// judged in the room during this process (st.seen, bounded), and the senders of r itself.
func (st *roomState) attribute(r *ReadResult) {
	onRoster := make(map[string]bool, len(st.roster))
	keysByName := make(map[string]map[string]struct{})
	see := func(name, key string) {
		if keysByName[name] == nil {
			keysByName[name] = make(map[string]struct{})
		}
		keysByName[name][key] = struct{}{}
	}
	for _, entry := range st.roster {
		key := senderKey(entry.public)
		onRoster[key] = true
		see(entry.aura.Name, key)
	}
	named := make(map[string]struct{}, len(st.seen))
	for _, seen := range st.seen {
		if _, done := named[seen.sender]; done {
			continue
		}
		named[seen.sender] = struct{}{}
		if aura, err := auraOfSenderKey(seen.sender); err == nil {
			see(aura.Name, seen.sender)
		}
	}
	senders := r.senders()
	for _, f := range senders {
		see(f.Sender, senderKey(f.key))
	}
	for _, f := range senders {
		key := senderKey(f.key)
		f.Left = !onRoster[key]
		f.SameName = len(keysByName[f.Sender]) > 1
		f.Unrecorded = st.unrecordedSender(key)
	}
}

// keptSender is the sender bound's keep set (counters.js keptSenders): this agent's own key and
// every key of the current roster are never refused nor displaced.
func (st *roomState) keptSender(key string) bool {
	if key == senderKey(st.member.Public) {
		return true
	}
	for _, entry := range st.roster {
		if senderKey(entry.public) == key {
			return true
		}
	}
	return false
}

// noteUnrecorded remembers the senders the bound refused (bounded), so the result marks their
// messages unrecorded, and forgets those the record holds by now (counter-records.js keeps
// conv.unrecorded the same way). A bound only makes the answer more conservative: a refused sender
// that finds the set full sets st.unrecordedFull, which stays set until the forgetting pass leaves
// the set below its bound again (unrecordedSender).
func (st *roomState) noteUnrecorded(refused []string) {
	for key := range st.unrecorded {
		if _, recorded := st.counters.Senders[key]; recorded {
			delete(st.unrecorded, key)
		}
	}
	if len(st.unrecorded) < maxUnrecordedSenders {
		st.unrecordedFull = false
	}
	if len(refused) == 0 {
		return
	}
	warn(CodeSenderUnrecorded)
	if st.unrecorded == nil {
		st.unrecorded = make(map[string]struct{})
	}
	for _, key := range refused {
		if len(st.unrecorded) < maxUnrecordedSenders {
			st.unrecorded[key] = struct{}{}
		} else if _, noted := st.unrecorded[key]; !noted {
			st.unrecordedFull = true
		}
	}
}

// unrecordedSender is whether a sender's messages say unrecorded: a sender noted unrecorded, and,
// while a refused sender could not be noted (unrecordedFull), every sender that is neither kept
// nor held by the record, since the one dropped may be any of them (fail closed).
func (st *roomState) unrecordedSender(key string) bool {
	if _, noted := st.unrecorded[key]; noted {
		return true
	}
	if !st.unrecordedFull || st.keptSender(key) {
		return false
	}
	_, recorded := st.counters.Senders[key]
	return !recorded
}

// senders is every From in r that names an authenticated sender (a broken message names none).
func (r *ReadResult) senders() []*From {
	out := make([]*From, 0, len(r.Messages)+len(r.Gaps)+len(r.Replays))
	for i := range r.Messages {
		out = append(out, &r.Messages[i].From)
	}
	for i := range r.Gaps {
		out = append(out, &r.Gaps[i].From)
	}
	for i := range r.Replays {
		out = append(out, &r.Replays[i].From)
	}
	named := out[:0]
	for _, f := range out {
		if f.key != nil {
			named = append(named, f)
		}
	}
	return named
}

// auraOfSenderKey is the aura of a sender recorded by senderKey.
func auraOfSenderKey(key string) (e2e.Aura, error) {
	public, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return e2e.Aura{}, err
	}
	return e2e.AuraOf(public)
}
