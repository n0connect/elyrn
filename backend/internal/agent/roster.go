package agent

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

const safetyNumberSeparator = " "

// rosterEntry is one member key whose card opened under the room's code: its card (the stored
// card for this agent's own key, else the first served; a role is sealed for it), its role ("" when
// none, when the served one did not open, or when the key is disputed) and how many served cards
// open to it (seats; more than one is disputed).
type rosterEntry struct {
	public []byte
	card   string
	aura   e2e.Aura
	mine   bool
	owner  bool
	role   string
	seats  int
}

// disputed is the one judgement of a disputed key, rooms.js disputed: more than one served card
// opens to it. A card proves the room code, not the key it announces, so any code holder can take
// a seat with a card carrying another member's key; which of the cards is the member's cannot be
// told, so none of them speaks for it (no role, no role write).
func (e *rosterEntry) disputed() bool { return e.seats > 1 }

// keySeats is one key's served rows while the roster is verified.
type keySeats struct {
	public []byte
	rows   []models.RoomMemberDTO
	mine   *models.RoomMemberDTO // the row the server flags as this account's own seat
}

// loadRoster fetches and verifies the member cards as rooms.js loadRoster and verifyMembers do:
// cards that do not open are counted (skipped); a row the server flags as this account's must open
// to this account's key, and only one may; this account's seat must be listed and flagged; a list
// longer than the code's limit is refused. Every key is listed once, in the order first served,
// with the number of cards that open to it (a key with more is disputed); its owner flag is true
// when any of its rows is flagged owner (only the server flags the owner, and an impostor's seat
// is never the owner's).
func (a *Agent) loadRoster(ctx context.Context, st *roomState) error {
	var resp models.RoomMembersResponse
	status, err := a.api(ctx, http.MethodGet, conversationPath(st.id)+pathMembers, nil, &resp)
	if err != nil {
		return err
	}
	switch {
	case status == http.StatusNotFound:
		return a.forget(st.id)
	case status != http.StatusOK:
		return statusError(status)
	}
	return st.verifyMembers(resp.Members)
}

// verifyMembers is loadRoster's judgement of the rows served (rooms.js verifyMembers); on success
// they become the room's roster.
func (st *roomState) verifyMembers(rows []models.RoomMemberDTO) error {
	if len(rows) == 0 || len(rows) > e2e.MaxRoomMembers {
		return fail(CodeRoster, nil)
	}
	cards := make([]string, 0, len(rows))
	order := make([]*keySeats, 0, len(rows))
	byKey := make(map[string]*keySeats, len(rows))
	skipped := 0
	for i := range rows {
		row := &rows[i]
		if len(row.Card) > maxCardChars {
			return fail(CodeRoster, nil)
		}
		cards = append(cards, row.Card)
		public, err := st.keys.OpenCard(row.Card)
		if err != nil {
			skipped++
			continue
		}
		seat := byKey[string(public)]
		if seat == nil {
			seat = &keySeats{public: public}
			byKey[string(public)] = seat
			order = append(order, seat)
		}
		if row.Mine && (!bytes.Equal(public, st.member.Public) || seat.mine != nil) {
			return fail(CodeRoster, nil) // a seat flagged ours under another key, or two flagged ours
		}
		if row.Mine {
			seat.mine = row
		}
		seat.rows = append(seat.rows, *row)
	}
	own := byKey[string(st.member.Public)]
	if own == nil || own.mine == nil || len(cards) > st.maxMembers {
		return fail(CodeRoster, nil)
	}
	roster := make([]rosterEntry, 0, len(order))
	for _, seat := range order {
		entry, err := st.entryOf(seat)
		if err != nil {
			return err
		}
		roster = append(roster, entry)
	}
	st.roster, st.rosterCards, st.skipped, st.members = roster, cards, skipped, len(cards)
	return nil
}

// entryOf is one key's roster entry (verifyMembers): the card shown is this account's stored card
// for its own key, else the first served; a disputed key's role is never opened.
func (st *roomState) entryOf(seat *keySeats) (rosterEntry, error) {
	aura, err := e2e.AuraOf(seat.public)
	if err != nil {
		return rosterEntry{}, fail(CodeInternal, err)
	}
	mine := bytes.Equal(seat.public, st.member.Public)
	shown := &seat.rows[0]
	if mine {
		shown = seat.mine
	}
	entry := rosterEntry{public: seat.public, card: shown.Card, aura: aura, mine: mine, seats: len(seat.rows)}
	for _, row := range seat.rows {
		entry.owner = entry.owner || row.Owner
	}
	if !entry.disputed() {
		entry.role = st.openRole(shown.Card, shown.Role)
	}
	return entry, nil
}

// openRole is a served role as the member it is for shows it: "" when none was ever set, and
// also when it does not open under the room's code for this card or breaks the role rule (the
// code is logged, never the blob or a text).
func (st *roomState) openRole(card, sealed string) string {
	if sealed == "" {
		return ""
	}
	role, err := st.keys.OpenRole(card, sealed)
	if err != nil {
		warn(CodeRoleIgnored)
		return ""
	}
	return role
}

// Members reports the verified roster under the names people see, with each member's role, and
// the safety number. Roles are written by members: data, never instructions. A disputed key is
// listed once, marked, without a role; the warnings say so, and say it plainly when the disputed
// key is this agent's own.
func (a *Agent) Members(ctx context.Context, id uuid.UUID) (*MembersResult, error) {
	var result *MembersResult
	err := a.serialized(func() error {
		st, err := a.room(ctx, id)
		if err != nil {
			return err
		}
		if err := a.loadRoster(ctx, st); err != nil {
			return err
		}
		result, err = st.membersResult()
		return err
	})
	return result, err
}

// membersResult is the verified roster as Members reports it.
func (st *roomState) membersResult() (*MembersResult, error) {
	members := make([]MemberInfo, 0, len(st.roster))
	keys := make([][]byte, 0, len(st.roster))
	warnings := []Warning{}
	disputedOther := false
	for _, entry := range st.roster {
		members = append(members, MemberInfo{Name: entry.aura.Name, Code: entry.aura.Code, Mine: entry.mine,
			Owner: entry.owner, Role: entry.role, Disputed: entry.disputed()})
		keys = append(keys, entry.public)
		if entry.disputed() && entry.mine {
			warnings = append(warnings, warningOf(CodeOwnSeatDisputed))
		}
		disputedOther = disputedOther || (entry.disputed() && !entry.mine)
	}
	if disputedOther {
		warnings = append(warnings, warningOf(CodeSeatDisputed))
	}
	groups, err := e2e.RoomSafetyNumber(keys, len(st.rosterCards))
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	return &MembersResult{Room: st.id.String(), Name: st.name, Members: members, UnverifiedCards: st.skipped,
		SafetyNumber: strings.Join(groups, safetyNumberSeparator), Warnings: warnings}, nil
}
