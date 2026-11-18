package agent

import (
	"strings"
	"testing"

	"elyrn/internal/e2e"
	"elyrn/internal/models"
)

// FuzzServedRoster: any member list built from this room's genuine cards, impostor cards for each
// member, a card that does not open, and arbitrary flags is either refused or verified into one
// entry per key, this agent's included, where a key with more than one card is disputed and shows
// no role, and every row counts as a seat.
// Run with: go test -tags test -run '^$' -fuzz '^FuzzServedRoster$' -fuzztime 60s ./internal/agent
func FuzzServedRoster(f *testing.F) {
	fx := newRoomFixture(f)
	pool := make([]string, 0, 2*len(fx.members)+1)
	for i := range fx.members {
		pool = append(pool, fx.members[i].Card, fx.impostorCard(f, i))
	}
	pool = append(pool, strings.Repeat("A", len(fx.members[0].Card)))
	roles := make([]string, len(pool))
	for i, card := range pool[:len(pool)-1] {
		roles[i] = fx.sealedRoleFor(f, card, "lider")
	}
	// Pairs of (card in pool, flags: bit 0 mine, bit 1 owner, bit 2 a role sealed for that card)
	f.Add([]byte{0, 1, 2, 0, 4, 0})             // honest
	f.Add([]byte{0, 1, 3, 6, 2, 0, 4, 0})       // an impostor of member 1 before its genuine card
	f.Add([]byte{0, 1, 1, 0, 2, 2, 4, 0, 6, 0}) // this agent's key under two cards
	f.Add([]byte{0, 1, 0, 1})                   // two seats flagged ours
	f.Fuzz(func(t *testing.T, ops []byte) {
		rows := make([]models.RoomMemberDTO, 0, len(ops)/2)
		for i := 0; i+1 < len(ops) && len(rows) < e2e.MaxRoomMembers; i += 2 {
			which, flags := int(ops[i])%len(pool), ops[i+1]
			row := models.RoomMemberDTO{Card: pool[which], Mine: flags&1 != 0, Owner: flags&2 != 0}
			if flags&4 != 0 {
				row.Role = roles[which]
			}
			rows = append(rows, row)
		}
		st := seatedState(fx)
		if err := st.verifyMembers(rows); err != nil {
			if CodeOf(err) != CodeRoster {
				t.Fatalf("refused with %s", CodeOf(err))
			}
			return
		}
		seats := make(map[string]int)
		for _, row := range rows {
			if public, err := fx.keys.OpenCard(row.Card); err == nil {
				seats[string(public)]++
			}
		}
		if len(st.roster) != len(seats) || len(st.rosterCards) != len(rows) {
			t.Fatalf("%d entries for %d keys, %d cards for %d rows", len(st.roster), len(seats), len(st.rosterCards), len(rows))
		}
		self := 0
		for _, entry := range st.roster {
			if entry.seats != seats[string(entry.public)] || (entry.disputed() && entry.role != "") {
				t.Fatalf("entry %+v for %d seats", entry, seats[string(entry.public)])
			}
			if entry.mine {
				self++
			}
		}
		if self != 1 {
			t.Fatalf("%d entries are this agent's", self)
		}
		if _, err := st.membersResult(); err != nil {
			t.Fatalf("membersResult: %v", err)
		}
	})
}
