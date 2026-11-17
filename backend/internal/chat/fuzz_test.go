package chat

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/e2e"
	"elyrn/internal/utils"
)

// Fuzz targets for the chat service's pure parsing, paging and clock rules (no database). Run
// one with: go test -tags test -run '^$' -fuzz '^FuzzParseRoomInput$' -fuzztime 60s ./internal/chat

const (
	// fuzzNowUnix is the fixed clock the fuzzed limits and retention rules are judged against
	fuzzNowUnix = int64(1767225600)
	// cardListSeparator splits one fuzzed string into a roster
	cardListSeparator = ","
	// maxFuzzRoster bounds the rosters compared with the client's digest (the client's own bound)
	maxFuzzRoster = e2e.MaxRoomMembers
)

// canonical returns base64url of n bytes of value b: a well-formed field of that size.
func canonical(n int, b byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{b}, n))
}

// FuzzParseRoomInput: accepted fields are canonical (the id formats back to itself, every
// base64url field re-encodes to its input at its exact size), and checkLimits admits only a
// member count within ROOM_MAX_MEMBERS and an expiry inside the window the room rules allow.
func FuzzParseRoomInput(f *testing.F) {
	id := "3b241101-e2bb-4255-8caf-4136c566a962"
	lookup, card, vault := canonical(utils.RoomLookupBytes, 1), canonical(utils.RoomCardBytes, 2), canonical(utils.RoomVaultBytes, 3)
	expiry := fuzzNowUnix + 2*int64(time.Hour/time.Second)
	f.Add(id, lookup, card, vault, config.MinRoomMembers, expiry)
	f.Add(strings.ToUpper(id), lookup, card, vault, config.MaxRoomMembersBound+1, expiry)
	f.Add(id, lookup+"A", card[1:], vault+"=", 0, int64(-1))
	f.Add(id, "\n"+lookup, card, vault, -1, int64(1)<<62)
	f.Add("", "", "", "", 0, int64(0))
	f.Fuzz(func(t *testing.T, id, lookup, card, vault string, maxMembers int, expiresAt int64) {
		in, err := ParseRoomInput(id, lookup, card, vault, maxMembers, expiresAt)
		if err != nil {
			return
		}
		if in.ID.String() != id || in.ID.Version() != 4 || base64.RawURLEncoding.EncodeToString(in.Lookup) != lookup ||
			len(in.Lookup) != utils.RoomLookupBytes || in.Card != card || in.Vault != vault {
			t.Fatalf("accepted non-canonical room fields %q %q %q %q", id, lookup, card, vault)
		}
		for field, size := range map[string]int{card: utils.RoomCardBytes, vault: utils.RoomVaultBytes} {
			if raw, err := base64.RawURLEncoding.Strict().DecodeString(field); err != nil || len(raw) != size ||
				base64.RawURLEncoding.EncodeToString(raw) != field {
				t.Fatalf("accepted the non-canonical field %q", field)
			}
		}
		now := time.Unix(fuzzNowUnix, 0)
		if checkLimits(in, now) != nil {
			return
		}
		ahead := in.ExpiresAt.Sub(now)
		if in.MaxMembers > config.GetRoomMaxMembers() || ahead < config.MinRoomTTLHours*time.Hour-expirySkew ||
			ahead > time.Duration(config.GetRoomMaxTTLHours()+config.RoomExpiryRoundHours)*time.Hour+expirySkew {
			t.Fatalf("limits admitted %d members expiring %v ahead", in.MaxMembers, ahead)
		}
	})
}

// FuzzRosterDigestMatchesClient is a differential check: for every roster a client can digest
// (1..32 canonical cards), the server's digest is byte for byte the client's; for any other
// roster the server refuses whenever a card is malformed.
func FuzzRosterDigestMatchesClient(f *testing.F) {
	a, b := canonical(utils.RoomCardBytes, 0xa0), canonical(utils.RoomCardBytes, 0x0b)
	f.Add(a + cardListSeparator + b)
	f.Add(b + cardListSeparator + a + cardListSeparator + a)
	f.Add(a)
	f.Add(a + cardListSeparator)
	f.Add(a + "=")
	f.Add("")
	f.Fuzz(func(t *testing.T, list string) {
		cards := strings.Split(list, cardListSeparator)
		server, serverErr := rosterDigest(cards)
		if len(cards) > maxFuzzRoster {
			return
		}
		client, clientErr := e2e.RosterDigest(cards)
		if (serverErr == nil) != (clientErr == nil) {
			t.Fatalf("server %v, client %v for %q", serverErr, clientErr, list)
		}
		if serverErr == nil && !bytes.Equal(server, client) {
			t.Fatalf("server and client digests differ for %q", list)
		}
	})
}

// cursorKinds is one more than the defined kinds, so an unknown kind is fuzzed too
const cursorKinds = 4

// FuzzMessageWindow: no window reaches below the reader's joined_seq (a room member never gets
// what was sent before they joined), a ceiling is either absent or at least FirstSeq, and the
// page limit is the configured one.
func FuzzMessageWindow(f *testing.F) {
	f.Add(uint8(CursorLatest), int64(0), int64(0), 200)
	f.Add(uint8(CursorAfter), int64(-5), int64(10), 1)
	f.Add(uint8(CursorBefore), int64(0), int64(10), 1)
	f.Add(uint8(CursorBefore), int64(-1)<<63, int64(1)<<62, 0)
	f.Add(uint8(cursorKinds-1), int64(7), int64(3), 5)
	f.Fuzz(func(t *testing.T, kind uint8, seq, joinedSeq int64, limit int) {
		cursor := PageCursor{Kind: CursorKind(kind % cursorKinds), Seq: seq}
		w := messageWindow(cursor, joinedSeq, limit)
		if w.Floor < joinedSeq || (w.Ceiling != 0 && w.Ceiling < FirstSeq) || w.Limit != limit {
			t.Fatalf("cursor %+v joined %d: window %+v", cursor, joinedSeq, w)
		}
		switch cursor.Kind {
		case CursorAfter:
			if w.Newest || w.Ceiling != 0 || w.Floor != max(seq, joinedSeq) {
				t.Fatalf("after %d: window %+v", seq, w)
			}
		case CursorBefore:
			if !w.Newest || w.Floor != joinedSeq || w.Ceiling != max(seq, FirstSeq) {
				t.Fatalf("before %d: window %+v", seq, w)
			}
		default:
			if !w.Newest || w.Ceiling != 0 || w.Floor != joinedSeq {
				t.Fatalf("latest: window %+v", w)
			}
		}
	})
}

// FuzzClockTrusted: retention never trusts a clock behind its last purge, always trusts the
// first pass on a fresh database, and after a boot refuses a clock far beyond the last purge.
func FuzzClockTrusted(f *testing.F) {
	f.Add(fuzzNowUnix, int64(0), int64(0))
	f.Add(fuzzNowUnix, fuzzNowUnix-60, fuzzNowUnix-3600)
	f.Add(fuzzNowUnix, int64(0), fuzzNowUnix+1)
	f.Add(fuzzNowUnix, int64(0), fuzzNowUnix-int64(3*maxRetentionGap()/time.Second))
	f.Fuzz(func(t *testing.T, nowSec, prevSec, markSec int64) {
		now, prev, mark := time.Unix(nowSec, 0), time.Time{}, time.Time{}
		if prevSec != 0 {
			prev = time.Unix(prevSec, 0) // wall-only readings: always steady
		}
		if markSec != 0 {
			mark = time.Unix(markSec, 0)
		}
		trusted := clockTrusted(now, prev, mark)
		switch {
		case mark.IsZero():
			if !trusted {
				t.Fatal("the first pass on a fresh database was refused")
			}
		case now.Before(mark):
			if trusted {
				t.Fatalf("a clock behind the last purge was trusted: now %v mark %v", now, mark)
			}
		case prev.IsZero() && now.After(mark.Add(maxRetentionGap())):
			if trusted {
				t.Fatalf("a boot far beyond the last purge was trusted: now %v mark %v", now, mark)
			}
		default:
			if !trusted {
				t.Fatalf("a steady clock was refused: now %v prev %v mark %v", now, prev, mark)
			}
		}
	})
}

// Operations FuzzPartCounter drives the stored-parts counter with, one per script byte
const (
	counterSet = iota
	counterReserve
	counterCommit
	counterRollBack
	counterMark
	counterDrop
	counterOps
)

// FuzzPartCounter runs arbitrary scripts of counts, reservations, settlements and deletions on a
// counter of its own: a reservation is granted only while the count is known and stored plus
// reserved stays below the limit, refused (ErrFileStoreFull) otherwise; nothing goes negative;
// a deletion marked before a recount subtracts nothing; a recount sets exactly its value.
func FuzzPartCounter(f *testing.F) {
	f.Add([]byte{counterReserve, 5, counterSet, 2, counterReserve, 3, counterReserve, 3, counterCommit, counterReserve, 3})
	f.Add([]byte{counterSet, 9, counterMark, counterSet, 9, counterDrop, 4})
	f.Add([]byte{counterSet, 1, counterMark, counterDrop, 200, counterReserve, 1, counterRollBack})
	f.Fuzz(func(t *testing.T, script []byte) {
		c := &partCounter{mu: utils.NewSafeMutex()}
		outstanding := int64(0)
		var marked uint64
		next := func(i *int) int64 {
			*i++
			if *i < len(script) {
				return int64(script[*i])
			}
			return 0
		}
		for i := 0; i < len(script); i++ {
			op := int(script[i]) % counterOps
			before := partCounter{known: c.known, stored: c.stored, reserved: c.reserved, generation: c.generation}
			switch op {
			case counterSet:
				n := next(&i)
				if err := c.set(n); err != nil || c.stored != n || !c.known || c.generation != before.generation+1 {
					t.Fatalf("set(%d) after %+v: stored %d known %v (%v)", n, before, c.stored, c.known, err)
				}
			case counterReserve:
				limit := next(&i)
				err := c.reserve(limit)
				granted := before.known && before.stored+before.reserved < limit
				if granted != (err == nil) || (err != nil && !errors.Is(err, ErrFileStoreFull)) {
					t.Fatalf("reserve(%d) after %+v answered %v", limit, before, err)
				}
				if err == nil {
					outstanding++
				}
			case counterCommit, counterRollBack:
				if outstanding == 0 {
					continue
				}
				committed := op == counterCommit
				if err := c.settle(committed); err != nil {
					t.Fatal(err)
				}
				outstanding--
				want := before.stored
				if committed {
					want++
				}
				if c.stored != want {
					t.Fatalf("settle(%v) moved stored from %d to %d", committed, before.stored, c.stored)
				}
			case counterMark:
				generation, err := c.mark()
				if err != nil {
					t.Fatal(err)
				}
				marked = generation
			case counterDrop:
				n := next(&i)
				if err := c.drop(n, marked); err != nil {
					t.Fatal(err)
				}
				if marked != before.generation && c.stored != before.stored {
					t.Fatalf("a deletion marked before a recount subtracted %d", before.stored-c.stored)
				}
			}
			if c.stored < 0 || c.reserved != outstanding {
				t.Fatalf("stored %d reserved %d with %d reservations outstanding", c.stored, c.reserved, outstanding)
			}
		}
	})
}
