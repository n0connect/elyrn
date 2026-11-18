package agent

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"elyrn/internal/e2e"
	"elyrn/internal/identity"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// The message-counter file (agent.counters.json beside agent.json, same permissions, written
// through writePrivate): per room the counterRecord, so that a restart neither repeats this
// account's counters (browsers would hide the repeats as replays while this agent reported them
// stored) nor forgets which counters it has seen from others.
//
//	{"version":1,"rooms":{"<room id>":{"seq":12,"mine":4,"senders":{"<public key>":7},"order":["<public key>"],"expires":1767225600}}}
//
// Policy. The file is written, empty, as soon as the identity file is (register), so every
// identity has one from its first run on and a healthy start logs nothing. A missing file is an
// empty one; for an identity that already existed it was expected, so it is logged as
// E_AGENT_STATE_REBUILT (an upgrade from a release without the file, or a lost file) and written
// again at once, empty, so the warning is not repeated by the next start: this account's
// counter is then rebuilt from the visible messages before its first send in each room, as
// before. A file that cannot be read is logged the same way and left alone (it may hold records
// once the disk recovers), so that warning repeats until it is fixed. A file that is present
// but malformed, of the wrong version or too large fails closed with E_AGENT_STATE_FILE: the
// operator restores or removes it. A room's record is written before every send (write-ahead),
// and after a read that raised it. "expires" is optional (records written before it was kept
// load as unknown) and is filled in from the room's verified code whenever the room is seen.
//
// Pruning (zero trust). The server is untrusted: it may omit a room from one listing or answer
// 404 for it, and a record dropped on that word would let old messages replay undetected
// afterwards. So a record is dropped only on facts the agent holds itself: the room's own
// expiry, from its code, lies more than expiredRoomGrace in the past (the room is then hidden
// too, rooms.go), or this agent left or burned the room itself. Past maxStateRooms records,
// the ones whose rooms expire soonest are evicted (rooms this agent holds right now last, so a
// send's write-ahead record stays), logged as E_AGENT_STATE_EVICTED.
const (
	stateVersion      = 1
	maxStateRooms     = maxListedConversations
	maxStateFileBytes = 16 << 20 // far above maxStateRooms rooms of maxTrackedSenders senders
)

type stateFile struct {
	Version int                       `json:"version"`
	Rooms   map[string]*counterRecord `json:"rooms"`
}

// counterState is the loaded file and where it lives.
type counterState struct {
	path  string
	rooms map[uuid.UUID]*counterRecord
}

// loadCounterState reads the file at path; existed says whether the identity was already there
// (then the file was expected: a missing one is reported and written again, empty).
func loadCounterState(path string, existed bool) (*counterState, error) {
	state := &counterState{path: path, rooms: make(map[uuid.UUID]*counterRecord)}
	raw, err := readPrivate(path, maxStateFileBytes, CodeStateFile)
	switch {
	case errors.Is(err, errUnreadable):
		warn(CodeStateRebuilt)
		return state, nil
	case err != nil:
		return nil, err
	case raw == nil:
		if existed {
			warn(CodeStateRebuilt)
			state.saveOrWarn(nil)
		}
		return state, nil
	}
	rooms, err := decodeCounterRooms(raw)
	if err != nil {
		return nil, err
	}
	state.rooms = rooms
	return state, nil
}

// decodeCounterRooms parses the content of a counter file: one object of the current version,
// read exactly (exactKeys), no unknown field, at most maxStateRooms valid records under canonical
// room ids.
func decodeCounterRooms(raw []byte) (map[uuid.UUID]*counterRecord, error) {
	if !exactKeys(raw, reflect.TypeFor[stateFile]()) {
		return nil, fail(CodeStateFile, nil)
	}
	var file stateFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil || decoder.More() || file.Version != stateVersion || len(file.Rooms) > maxStateRooms {
		return nil, fail(CodeStateFile, err)
	}
	rooms := make(map[uuid.UUID]*counterRecord, len(file.Rooms))
	for key, record := range file.Rooms {
		id, ok := utils.ParseCanonicalUUIDv4(key)
		if !ok || !validRecord(record) {
			return nil, fail(CodeStateFile, nil)
		}
		rooms[id] = record
	}
	return rooms, nil
}

// exactKeys holds the counter file to the rule of e2e's exact reader (e2e.ExactObject), before
// encoding/json binds it: the whole file valid UTF-8 without a lone surrogate escape, and every
// object that fills a struct keyed by its fields' JSON names byte for byte (encoding/json binds
// "SEQ" or a Kelvin sign to a field by case folding). An object filling a map is read exactly too;
// null is left to encoding/json, which reads it as empty. Scalars and arrays are left to it as well:
// the bytes were checked as a whole by the outermost ExactObject.
func exactKeys(raw json.RawMessage, t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Pointer:
		return bytes.Equal(raw, jsonNull) || exactKeys(raw, t.Elem())
	case reflect.Map:
		if bytes.Equal(raw, jsonNull) {
			return true
		}
		members, err := e2e.ExactObject(raw)
		if err != nil {
			return false
		}
		for _, value := range members {
			if !exactKeys(value, t.Elem()) {
				return false
			}
		}
		return true
	case reflect.Struct:
		members, err := e2e.ExactObject(raw)
		if err != nil {
			return false
		}
		for key, value := range members {
			field, ok := fieldByJSONName(t, key)
			if !ok || !exactKeys(value, field.Type) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// jsonNull is the JSON literal null.
var jsonNull = []byte("null")

// fieldByJSONName is t's field whose JSON name (its tag's first part) is exactly name.
func fieldByJSONName(t reflect.Type, name string) (reflect.StructField, bool) {
	for field := range t.Fields() {
		tagName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if tagName == name {
			return field, true
		}
	}
	return reflect.StructField{}, false
}

func validRecord(r *counterRecord) bool {
	if r == nil || !isSeq(r.Seq) || !isSeq(r.Mine) || !isSeq(r.Expires) || len(r.Senders) > maxTrackedSenders {
		return false
	}
	if r.Senders == nil {
		r.Senders = make(map[string]int64)
	}
	for key, counter := range r.Senders {
		if _, ok := utils.DecodeExact(key, identity.KeySize); !ok || counter < 1 || !isSeq(counter) {
			return false
		}
	}
	return validOrder(r)
}

// validOrder checks that Order lists every key of Senders once and nothing else. A record written
// before Order was kept has none: its senders are taken as recorded in key order, so a later
// displacement picks among them deterministically. An empty order is no order: "order" is written
// omitempty, so a record without senders always loads with none (and saves and loads back alike).
func validOrder(r *counterRecord) bool {
	if len(r.Order) == 0 && len(r.Senders) == 0 {
		r.Order = nil
		return true
	}
	if r.Order == nil {
		r.Order = slices.Sorted(maps.Keys(r.Senders))
		return true
	}
	if len(r.Order) != len(r.Senders) {
		return false
	}
	listed := make(map[string]struct{}, len(r.Order))
	for _, key := range r.Order {
		if _, ok := r.Senders[key]; !ok {
			return false
		}
		if _, dup := listed[key]; dup {
			return false
		}
		listed[key] = struct{}{}
	}
	return true
}

// record returns the room's record, creating an empty one, and notes the room's expiry from its
// verified code (expires, unix seconds).
func (s *counterState) record(id uuid.UUID, expires int64) *counterRecord {
	r := s.rooms[id]
	if r == nil {
		r = newCounterRecord()
		s.rooms[id] = r
	}
	r.Expires = expires
	return r
}

// expiredLongAgo reports whether a room that expires at expires (unix seconds, 0 for unknown)
// lies more than expiredRoomGrace in the past at now: the agent's own fact, never the server's.
func expiredLongAgo(expires int64, now time.Time) bool {
	return expires > 0 && now.After(time.Unix(expires, 0).Add(expiredRoomGrace))
}

// pruneExpired drops the records of rooms whose own expiry lies more than expiredRoomGrace in
// the past; it reports whether any was dropped.
func (s *counterState) pruneExpired(now time.Time) bool {
	pruned := false
	for id, record := range s.rooms {
		if expiredLongAgo(record.Expires, now) {
			delete(s.rooms, id)
			pruned = true
		}
	}
	return pruned
}

// evict keeps at most maxStateRooms records: past the bound, the records whose rooms expire
// soonest go first (an unknown expiry counts as the soonest), those of rooms in held last.
func (s *counterState) evict(held map[uuid.UUID]*roomState) {
	excess := len(s.rooms) - maxStateRooms
	if excess <= 0 {
		return
	}
	ids := make([]uuid.UUID, 0, len(s.rooms))
	for id := range s.rooms {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int {
		if heldA, heldB := held[a] != nil, held[b] != nil; heldA != heldB {
			if heldA {
				return 1
			}
			return -1
		}
		return cmp.Compare(s.rooms[a].Expires, s.rooms[b].Expires)
	})
	for _, id := range ids[:excess] {
		delete(s.rooms, id)
	}
	warn(CodeStateEvicted)
}

// save writes the whole file atomically, without the records of rooms long expired and within
// maxStateRooms records (evict).
func (s *counterState) save(held map[uuid.UUID]*roomState) error {
	s.pruneExpired(time.Now())
	s.evict(held)
	raw, err := s.encode()
	if err != nil {
		return err
	}
	return writePrivate(s.path, raw, true, CodeStateFile)
}

// encode is the content of the counter file for the records held now (decodeCounterRooms reads
// it back).
func (s *counterState) encode() ([]byte, error) {
	file := stateFile{Version: stateVersion, Rooms: make(map[string]*counterRecord, len(s.rooms))}
	for id, record := range s.rooms {
		file.Rooms[id.String()] = record
	}
	raw, err := json.Marshal(&file)
	if err != nil {
		return nil, fail(CodeStateFile, err)
	}
	return raw, nil
}

// drop forgets one room's record, only once this agent left or burned the room itself; it
// reports whether there was one.
func (s *counterState) drop(id uuid.UUID) bool {
	if _, ok := s.rooms[id]; !ok {
		return false
	}
	delete(s.rooms, id)
	return true
}

// senderKey is how a member public key is spelled in a record.
func senderKey(public []byte) string {
	return base64.RawURLEncoding.EncodeToString(public)
}

// saveOrWarn is save where a failure is only logged: what it records is already in memory, and
// the next write carries it (a send's write-ahead fails closed there).
func (s *counterState) saveOrWarn(held map[uuid.UUID]*roomState) {
	if err := s.save(held); err != nil {
		warn(CodeStateFile)
	}
}

// persistCounters writes the counter file. A send must not go out unless this succeeded
// (write-ahead); after a read or a registration, a failure is only logged
// (persistCountersOrWarn): the read already happened, and the next write carries the change.
func (a *Agent) persistCounters() error {
	return a.counters.save(a.rooms)
}

func (a *Agent) persistCountersOrWarn() {
	a.counters.saveOrWarn(a.rooms)
}
