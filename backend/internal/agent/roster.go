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

// rosterEntry is one member whose card opened under the room's code.
type rosterEntry struct {
	public []byte
	aura   e2e.Aura
	mine   bool
	owner  bool
}

// loadRoster fetches and verifies the member cards, as rooms.js loadRoster does: cards that do
// not open (or repeat a key) are counted and skipped; a card the server attributes to this
// account must be this account's; a roster without this account, or longer than the code's
// limit, is refused.
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
	case len(resp.Members) == 0 || len(resp.Members) > e2e.MaxRoomMembers:
		return fail(CodeRoster, nil)
	}
	cards := make([]string, 0, len(resp.Members))
	roster := make([]rosterEntry, 0, len(resp.Members))
	seen := make(map[string]struct{}, len(resp.Members))
	skipped := 0
	for _, entry := range resp.Members {
		if len(entry.Card) > maxCardChars {
			return fail(CodeRoster, nil)
		}
		cards = append(cards, entry.Card)
		public, err := st.keys.OpenCard(entry.Card)
		if err != nil {
			skipped++
			continue
		}
		mine := bytes.Equal(public, st.member.Public)
		if entry.Mine && !mine {
			return fail(CodeRoster, nil) // the server misattributes a card
		}
		if _, dup := seen[string(public)]; (mine && !entry.Mine) || dup {
			skipped++ // someone announcing a key already listed (or ours) adds nobody
			continue
		}
		seen[string(public)] = struct{}{}
		aura, err := e2e.AuraOf(public)
		if err != nil {
			return fail(CodeInternal, err)
		}
		roster = append(roster, rosterEntry{public: public, aura: aura, mine: mine, owner: entry.Owner})
	}
	if _, self := seen[string(st.member.Public)]; !self || len(cards) > st.maxMembers {
		return fail(CodeRoster, nil)
	}
	st.roster, st.rosterCards, st.skipped, st.members = roster, cards, skipped, len(cards)
	return nil
}

// Members reports the verified roster under the names people see, and the safety number.
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
		members := make([]MemberInfo, 0, len(st.roster))
		keys := make([][]byte, 0, len(st.roster))
		for _, entry := range st.roster {
			members = append(members, MemberInfo{Name: entry.aura.Name, Code: entry.aura.Code, Mine: entry.mine, Owner: entry.owner})
			keys = append(keys, entry.public)
		}
		groups, err := e2e.RoomSafetyNumber(keys)
		if err != nil {
			return fail(CodeInternal, err)
		}
		result = &MembersResult{Room: id.String(), Name: st.name, Members: members, UnverifiedCards: st.skipped,
			SafetyNumber: strings.Join(groups, safetyNumberSeparator)}
		return nil
	})
	return result, err
}
