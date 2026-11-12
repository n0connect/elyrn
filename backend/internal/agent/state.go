package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"

	"elyrn/internal/identity"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// The message-counter file (agent.counters.json beside agent.json, same permissions, written
// through writePrivate): per room the counterRecord, so that a restart neither repeats this
// account's counters (browsers would hide the repeats as replays while this agent reported them
// stored) nor forgets which counters it has seen from others.
//
//	{"version":1,"rooms":{"<room id>":{"seq":12,"mine":4,"senders":{"<public key>":7}}}}
//
// Policy. A missing file is an empty one; for an identity that already existed it is logged
// as E_AGENT_STATE_REBUILT (an upgrade from a release without the file, or a lost file): this
// account's counter is then rebuilt from the visible messages before its first send in each
// room, as before. A file that cannot be read is treated the same way. A file that is present
// but malformed, of the wrong version or too large fails closed with E_AGENT_STATE_FILE: the
// operator restores or removes it. A room's record is written before every send (write-ahead),
// and after a read that raised it; rooms no longer listed are pruned.
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

// loadCounterState reads the file at path; existed says whether the identity was already there.
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
		}
		return state, nil
	}
	var file stateFile
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil || decoder.More() || file.Version != stateVersion || len(file.Rooms) > maxStateRooms {
		return nil, fail(CodeStateFile, err)
	}
	for key, record := range file.Rooms {
		id, ok := utils.ParseCanonicalUUIDv4(key)
		if !ok || !validRecord(record) {
			return nil, fail(CodeStateFile, nil)
		}
		state.rooms[id] = record
	}
	return state, nil
}

func validRecord(r *counterRecord) bool {
	if r == nil || !isSeq(r.Seq) || !isSeq(r.Mine) || len(r.Senders) > maxTrackedSenders {
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
	return true
}

// record returns the room's record, creating an empty one.
func (s *counterState) record(id uuid.UUID) *counterRecord {
	r := s.rooms[id]
	if r == nil {
		r = newCounterRecord()
		s.rooms[id] = r
	}
	return r
}

// save writes the whole file atomically, keeping at most maxStateRooms rooms: beyond that the
// rooms this agent does not hold now are dropped first.
func (s *counterState) save(held map[uuid.UUID]*roomState) error {
	if len(s.rooms) > maxStateRooms {
		for id := range s.rooms {
			if held[id] == nil {
				delete(s.rooms, id)
			}
		}
		if len(s.rooms) > maxStateRooms {
			return fail(CodeStateFile, nil)
		}
	}
	file := stateFile{Version: stateVersion, Rooms: make(map[string]*counterRecord, len(s.rooms))}
	for id, record := range s.rooms {
		file.Rooms[id.String()] = record
	}
	raw, err := json.Marshal(&file)
	if err != nil {
		return fail(CodeStateFile, err)
	}
	return writePrivate(s.path, raw, true, CodeStateFile)
}

// prune drops the records of rooms not in keep; it reports whether any was dropped.
func (s *counterState) prune(keep map[uuid.UUID]*roomState) bool {
	pruned := false
	for id := range s.rooms {
		if keep[id] == nil {
			delete(s.rooms, id)
			pruned = true
		}
	}
	return pruned
}

// drop forgets one room's record; it reports whether there was one.
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

// persistCounters writes the counter file. A send must not go out unless this succeeded
// (write-ahead); after a read, a failure is only logged: the read already happened, and the
// next write carries the change.
func (a *Agent) persistCounters() error {
	return a.counters.save(a.rooms)
}

func (a *Agent) persistCountersAfterRead() {
	if err := a.persistCounters(); err != nil {
		warn(CodeStateFile)
	}
}
