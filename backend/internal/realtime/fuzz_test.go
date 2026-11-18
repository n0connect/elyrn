package realtime

import (
	"errors"
	"strconv"
	"testing"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzHubOperations$' -fuzztime 60s ./internal/realtime

// Hub operations a fuzzed program is made of: an opcode byte and an argument byte each
const (
	opSubscribe = iota
	opCancel
	opPublish
	opKick
	opDrain
	opMark // read a tag's generation now; that tag's next subscribe uses it
	hubOps

	hubOpBytes = 2
	// fuzzTags and fuzzClients are small, so programs hit the per-member and per-client caps
	fuzzTags    = 6
	fuzzClients = 3
	// fuzzClientKeys covers the clients plus the empty key, which is always refused
	fuzzClientKeys = fuzzClients + 1
)

// subscription is the model of one Subscribe the hub granted.
type subscription struct {
	tag, client string
	ch          <-chan Event
	cancel      func()
	live        bool
	buffered    int
}

func fuzzTag(b byte) string { return "tag-" + strconv.Itoa(int(b)%fuzzTags) }
func fuzzClient(b byte) string {
	return []string{"", "client-a", "client-b", "client-c"}[int(b)%fuzzClientKeys]
}

// closedAfterDrain reports whether ch is closed, reading at most its buffer first.
func closedAfterDrain(ch <-chan Event) bool {
	for range subscriberBuffer + 1 {
		select {
		case _, ok := <-ch:
			if !ok {
				return true
			}
		default:
			return false
		}
	}
	return false
}

// mark is the model of a generation read for a tag (opMark) that its next subscribe uses.
type mark struct {
	generation uint64
	kicked     bool // the tag was kicked since the read: the subscribe must be refused
}

// FuzzHubOperations runs arbitrary sequences of subscribe, cancel (repeated too), publish, kick,
// drain and generation reads against a model: the hub grants exactly what the per-member,
// per-client and total caps allow, and refuses a subscribe whose generation was read before a
// kick of its tag (and only that one), a poke reaches exactly the live subscribers of its tags
// (dropped only on a full buffer), a cancelled or kicked stream is closed and never sent on
// again, and the hub's counts always equal the live streams.
func FuzzHubOperations(f *testing.F) {
	f.Add([]byte{opSubscribe, 1, opPublish, 1, opDrain, 0})
	f.Add([]byte{opSubscribe, 1, opSubscribe, 1, opSubscribe, 1, opSubscribe, 1, opSubscribe, 1, opKick, 1, opPublish, 1})
	f.Add([]byte{opSubscribe, 0, opCancel, 0, opCancel, 0, opPublish, 0})
	f.Add([]byte{opMark, 1, opKick, 1, opSubscribe, 1, opMark, 1, opKick, 2, opSubscribe, 1})
	f.Fuzz(func(t *testing.T, program []byte) {
		h := NewHub()
		var subs []*subscription
		perTag, perClient, total := map[string]int{}, map[string]int{}, 0
		marks := map[string]*mark{}
		for op := 0; op+hubOpBytes <= len(program); op += hubOpBytes {
			arg := program[op+1]
			switch program[op] % hubOps {
			case opMark:
				generation, err := h.Generation(fuzzTag(arg))
				if err != nil {
					t.Fatalf("op %d: Generation: %v", op, err)
				}
				marks[fuzzTag(arg)] = &mark{generation: generation}
			case opSubscribe:
				tag, client := fuzzTag(arg), fuzzClient(arg/fuzzTags)
				generation, err := h.Generation(tag)
				if err != nil {
					t.Fatalf("op %d: Generation: %v", op, err)
				}
				revoked := false
				if m, ok := marks[tag]; ok {
					generation, revoked = m.generation, m.kicked
					delete(marks, tag)
				}
				want := client != "" && !revoked && total < MaxSubscribersTotal && perTag[tag] < MaxSubscribersPerMember && perClient[client] < MaxSubscribersPerClient
				ch, cancel, err := h.Subscribe(tag, client, generation)
				if (err == nil) != want {
					t.Fatalf("op %d: Subscribe(%s, %q, stale %v) = %v, model %v", op, tag, client, revoked, err, want)
				}
				if client != "" && revoked && !errors.Is(err, ErrRevokedSinceMark) {
					t.Fatalf("op %d: a subscribe after a kick of %s answered %v, want ErrRevokedSinceMark", op, tag, err)
				}
				if err == nil {
					subs = append(subs, &subscription{tag: tag, client: client, ch: ch, cancel: cancel, live: true})
					perTag[tag]++
					perClient[client]++
					total++
				}
			case opCancel, opKick:
				var picked []*subscription
				if program[op]%hubOps == opCancel {
					if len(subs) == 0 {
						continue
					}
					s := subs[int(arg)%len(subs)]
					s.cancel()
					picked = append(picked, s)
				} else {
					if err := h.Kick(fuzzTag(arg)); err != nil {
						t.Fatalf("op %d: Kick: %v", op, err)
					}
					if m, ok := marks[fuzzTag(arg)]; ok {
						m.kicked = true
					}
					for _, s := range subs {
						if s.tag == fuzzTag(arg) {
							picked = append(picked, s)
						}
					}
				}
				for _, s := range picked {
					if s.live {
						s.live = false
						perTag[s.tag]--
						perClient[s.client]--
						total--
					}
					if !closedAfterDrain(s.ch) {
						t.Fatalf("op %d: a removed stream of %s is still open", op, s.tag)
					}
					s.buffered = 0
				}
			case opPublish:
				tags := []string{fuzzTag(arg), fuzzTag(arg / fuzzTags)}
				ev := Event{Kind: KindMessage, ConversationID: strconv.Itoa(op)}
				h.Publish(tags, ev)
				for _, s := range subs {
					targeted := s.tag == tags[0] || s.tag == tags[1]
					if s.live && targeted && s.buffered < subscriberBuffer {
						s.buffered++
						if tags[0] == tags[1] && s.buffered < subscriberBuffer {
							s.buffered++ // a tag listed twice is delivered twice
						}
					}
					if s.live && len(s.ch) != s.buffered {
						t.Fatalf("op %d: stream of %s holds %d pokes, model %d", op, s.tag, len(s.ch), s.buffered)
					}
				}
			case opDrain:
				if len(subs) == 0 {
					continue
				}
				s := subs[int(arg)%len(subs)]
				if s.live {
					for range s.buffered {
						if ev, ok := <-s.ch; !ok || ev.Kind != KindMessage {
							t.Fatalf("op %d: drained %+v ok=%v", op, ev, ok)
						}
					}
					s.buffered = 0
				}
			}
			if err := h.mu.Lock(); err != nil {
				t.Fatalf("lock: %v", err)
			}
			counts := h.total == total && len(h.clients) == countPositive(perClient) && len(h.subs) == countPositive(perTag)
			h.mu.Unlock()
			if !counts {
				t.Fatalf("op %d: hub counts differ from the live streams (total %d, model %d)", op, h.total, total)
			}
		}
		for _, s := range subs {
			s.cancel() // idempotent: a second cancel of a removed stream must not panic
		}
	})
}

// countPositive counts the keys of m whose count is above zero (the hub deletes empty ones).
func countPositive(m map[string]int) int {
	n := 0
	for _, v := range m {
		if v > 0 {
			n++
		}
	}
	return n
}
