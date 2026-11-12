package agent

import (
	"context"
	"net/http"
	"time"

	"elyrn/internal/e2e"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// roomState is one verified room: the keys derived from its code and what this agent has seen.
type roomState struct {
	id         uuid.UUID
	name       string
	selfName   string
	vault      string
	keys       *e2e.Room
	member     *e2e.RoomMember
	maxMembers int
	expiresAt  time.Time
	owner      bool
	members    int
	lastSeq    int64
	readSeq    int64

	roster      []rosterEntry // valid cards only
	rosterCards []string      // every card as served: the digest covers them all
	skipped     int           // cards that failed to open: counted, never wrapped for

	countersKnown bool             // every visible message was read once, so myMaxN is final
	myMaxN        int64            // this account's highest counter in the room
	peerLastN     map[string]int64 // per sender key: their highest counter seen
	pendingGaps   []Gap            // found while syncing counters, reported by the next read
}

func isCount(value, max int) bool { return value >= 0 && value <= max }

func isSeq(value int64) bool { return value >= 0 && value <= maxSafeSeq }

func conversationPath(id uuid.UUID) string { return pathConversations + "/" + id.String() }

func formatHour(hour int64) string {
	return time.Unix(hour*hourSeconds, 0).UTC().Format(time.RFC3339)
}

// adopt verifies a listed room against the code its vault holds, as rooms.js adopt does: any
// mismatch and the room is refused (the caller hides it).
func (a *Agent) adopt(item *models.ConversationDTO) (*roomState, error) {
	view := item.Room
	id, ok := utils.ParseCanonicalUUIDv4(item.ID)
	if view == nil || !ok || item.PeerPublicKey != "" || !isCount(view.MaxMembers, e2e.MaxRoomMembers) ||
		view.ExpiresAt <= 0 || !isCount(view.Members, e2e.MaxRoomMembers) || !isCount(view.Notes, e2e.MaxRoomMembers) ||
		!isSeq(item.LastSeq) || !isSeq(item.ReadSeq) {
		return nil, fail(CodeServerAnswer, nil)
	}
	code, err := e2e.OpenVault(a.root, id, view.Vault)
	if err != nil {
		return nil, fail(CodeRoomVerify, err)
	}
	defer zeroBytes(code.Secret)
	if code.MaxMembers != view.MaxMembers || int64(code.ExpiresHour)*hourSeconds != view.ExpiresAt {
		return nil, fail(CodeRoomVerify, nil)
	}
	return a.roomFromCode(id, code, view.Vault, item)
}

// roomFromCode derives the keys and names of a room whose code is verified.
func (a *Agent) roomFromCode(id uuid.UUID, code *e2e.RoomCode, vault string, item *models.ConversationDTO) (*roomState, error) {
	keys, err := e2e.DeriveRoom(code.Secret)
	if err != nil || keys.ID != id {
		return nil, fail(CodeRoomVerify, err)
	}
	member, err := keys.Member(a.root)
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	roomAura, err := e2e.RoomAura(id)
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	self, err := e2e.AuraOf(member.Public)
	if err != nil {
		return nil, fail(CodeInternal, err)
	}
	st := &roomState{
		id: id, name: roomAura.Name, selfName: self.Name, vault: vault, keys: keys, member: member,
		maxMembers: code.MaxMembers, expiresAt: time.Unix(int64(code.ExpiresHour)*hourSeconds, 0),
		peerLastN: make(map[string]int64),
	}
	return st, st.refreshView(item)
}

// refreshView takes the listing's counters; the code and keys never change.
func (st *roomState) refreshView(item *models.ConversationDTO) error {
	view := item.Room
	if view == nil || view.Vault != st.vault || !isCount(view.Members, e2e.MaxRoomMembers) ||
		!isCount(view.Notes, e2e.MaxRoomMembers) || !isSeq(item.LastSeq) || !isSeq(item.ReadSeq) {
		return fail(CodeServerAnswer, nil)
	}
	st.owner, st.members, st.lastSeq, st.readSeq = view.Owner, view.Members, item.LastSeq, item.ReadSeq
	return nil
}

// listRooms refreshes the verified rooms from the server's listing. One-to-one conversations
// are skipped (design D5); a room that fails verification is hidden, never shown. The rooms come
// back in the server's order (newest first).
func (a *Agent) listRooms(ctx context.Context) ([]*roomState, error) {
	var resp models.ConversationsResponse
	status, err := a.api(ctx, http.MethodGet, pathConversations, nil, &resp)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(status)
	}
	if len(resp.Conversations) > maxListedConversations {
		return nil, fail(CodeServerAnswer, nil)
	}
	next := make(map[uuid.UUID]*roomState, len(resp.Conversations))
	ordered := make([]*roomState, 0, len(resp.Conversations))
	for i := range resp.Conversations {
		item := &resp.Conversations[i]
		if item.Room == nil {
			continue
		}
		st, err := a.verifiedRoom(item)
		if err != nil {
			logger.Warn("a listed room failed verification and is hidden")
			continue
		}
		if next[st.id] == nil {
			next[st.id] = st
			ordered = append(ordered, st)
		}
	}
	a.rooms = next
	return ordered, nil
}

// verifiedRoom keeps what this agent knows of a room it already verified under the same vault.
func (a *Agent) verifiedRoom(item *models.ConversationDTO) (*roomState, error) {
	if id, ok := utils.ParseCanonicalUUIDv4(item.ID); ok {
		if known := a.rooms[id]; known != nil && known.vault == item.Room.Vault {
			return known, known.refreshView(item)
		}
	}
	return a.adopt(item)
}

// room returns a verified room this account is in.
func (a *Agent) room(ctx context.Context, id uuid.UUID) (*roomState, error) {
	if st := a.rooms[id]; st != nil {
		return st, nil
	}
	if _, err := a.listRooms(ctx); err != nil {
		return nil, err
	}
	if st := a.rooms[id]; st != nil {
		return st, nil
	}
	return nil, fail(CodeRoomUnknown, nil)
}

// forget drops a room the server no longer serves to this account.
func (a *Agent) forget(id uuid.UUID) error {
	delete(a.rooms, id)
	return fail(CodeRoomUnknown, nil)
}

// Rooms lists the verified rooms this account is in.
func (a *Agent) Rooms(ctx context.Context) (*RoomsResult, error) {
	result := &RoomsResult{Rooms: []RoomInfo{}}
	err := a.serialized(func() error {
		listed, err := a.listRooms(ctx)
		if err != nil {
			return err
		}
		for _, st := range listed {
			result.Rooms = append(result.Rooms, RoomInfo{
				Room: st.id.String(), Name: st.name, Members: st.members, MaxMembers: st.maxMembers, Owner: st.owner,
				ExpiresAt: st.expiresAt.UTC().Format(time.RFC3339), Unread: max(st.lastSeq-st.readSeq, 0),
			})
		}
		return nil
	})
	return result, err
}

// Leave gives up this account's seat; the owner's leave burns the room for everyone.
func (a *Agent) Leave(ctx context.Context, id uuid.UUID) (*Left, error) {
	var result *Left
	err := a.serialized(func() error {
		st, err := a.room(ctx, id)
		if err != nil {
			return err
		}
		status, err := a.api(ctx, http.MethodDelete, conversationPath(id), nil, nil)
		if err != nil {
			return err
		}
		switch status {
		case http.StatusNoContent:
			delete(a.rooms, id)
			result = &Left{Room: id.String(), Burned: st.owner}
			return nil
		case http.StatusNotFound:
			return a.forget(id)
		default:
			return statusError(status)
		}
	})
	return result, err
}
