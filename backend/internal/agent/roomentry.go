package agent

import (
	"context"
	"net/http"
	"strings"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/e2e"
	"elyrn/internal/models"
)

// CreateRoom draws a room code, pays a proof of work and stores the room, as rooms.js create
// does. The code in the result is the room's only key: whoever holds it can join.
func (a *Agent) CreateRoom(ctx context.Context, maxMembers, ttlHours int) (*RoomCreated, error) {
	var result *RoomCreated
	err := a.serialized(func() error {
		if err := a.ensureSession(ctx); err != nil {
			return err
		}
		if maxMembers < MinRoomMembers || maxMembers > a.limits.RoomMaxMembers ||
			ttlHours < MinRoomTTLHours || ttlHours > a.limits.RoomMaxTTLHours {
			return fail(CodeRoomLimit, nil)
		}
		for attempt := 0; attempt < maxCreateAttempts; attempt++ {
			code, err := e2e.NewRoomCode(maxMembers, uint32(time.Now().Unix()/hourSeconds+int64(ttlHours)+config.RoomExpiryRoundHours))
			if err != nil {
				return fail(CodeInternal, err)
			}
			st, err := a.createOnce(ctx, code)
			if err == nil && st != nil {
				result = &RoomCreated{Room: st.id.String(), Name: st.name, Code: code.String(),
					MaxMembers: st.maxMembers, ExpiresAt: formatHour(int64(code.ExpiresHour))}
			}
			zeroBytes(code.Secret)
			if err != nil || st != nil {
				return err
			}
		}
		return fail(CodeRoomCreate, nil)
	})
	return result, err
}

// createOnce stores one room; nil, nil means its id was taken (409): draw a new code.
func (a *Agent) createOnce(ctx context.Context, code *e2e.RoomCode) (*roomState, error) {
	keys, member, vault, err := a.seat(code)
	if err != nil {
		return nil, err
	}
	solution, err := a.proofOfWork(ctx)
	if err != nil {
		return nil, err
	}
	var resp models.ConversationResponse
	status, err := a.api(ctx, http.MethodPost, pathRooms, models.CreateRoomRequest{
		ID: keys.ID.String(), Lookup: keys.Lookup, MaxMembers: code.MaxMembers,
		ExpiresAt: code.ExpiresAt(), Card: member.Card, Vault: vault, PoW: solution,
	}, &resp)
	switch {
	case err != nil && CodeOf(err) == CodeNetwork:
		return a.settleLost(ctx, keys, err)
	case err != nil:
		return nil, err
	case status == http.StatusConflict:
		return nil, nil
	case status == http.StatusCreated:
		return a.settle(&resp.Conversation, keys)
	default:
		return nil, powStatusError(status)
	}
}

// settleLost answers a create whose answer was lost: the server may have stored the room, and
// a retry would make a second one. If the listing holds it (verified against the code, as any
// listed room), the create succeeded; otherwise the original network failure stands.
func (a *Agent) settleLost(ctx context.Context, keys *e2e.Room, lost error) (*roomState, error) {
	if _, err := a.listRooms(ctx); err != nil {
		return nil, lost
	}
	if st := a.rooms[keys.ID]; st != nil {
		logger.Info("a room create whose answer was lost was found stored")
		return st, nil
	}
	return nil, lost
}

// JoinRoom takes a seat in the room a code opens.
func (a *Agent) JoinRoom(ctx context.Context, codeText string) (*RoomJoined, error) {
	var result *RoomJoined
	err := a.serialized(func() error {
		// The code is judged before anything is spent: a malformed or expired code never
		// creates the account (two proofs of work) or opens a session
		code, err := e2e.ParseRoomCode(strings.TrimSpace(codeText))
		if err != nil {
			return fail(CodeRoomCode, err)
		}
		defer zeroBytes(code.Secret)
		if code.ExpiresAt() <= time.Now().Unix() {
			return fail(CodeRoomExpired, nil)
		}
		if err := a.ensureSession(ctx); err != nil {
			return err
		}
		keys, member, vault, err := a.seat(code)
		if err != nil {
			return err
		}
		// A known room under other limits is a doctored code: the server refuses it too
		if st, ok := a.rooms[keys.ID]; ok && (st.maxMembers != code.MaxMembers || st.expiresAt.Unix() != code.ExpiresAt()) {
			return fail(CodeRoomCode, nil)
		}
		var resp models.ConversationResponse
		status, err := a.api(ctx, http.MethodPost, pathRoomsJoin, models.JoinRoomRequest{ID: keys.ID.String(), Lookup: keys.Lookup,
			Card: member.Card, Vault: vault, MaxMembers: code.MaxMembers, ExpiresAt: code.ExpiresAt()}, &resp)
		switch {
		case err != nil:
			return err
		case status == http.StatusOK || status == http.StatusCreated:
			st, err := a.settle(&resp.Conversation, keys)
			if err != nil {
				return err
			}
			result = &RoomJoined{Room: st.id.String(), Name: st.name, Members: st.members, ExpiresAt: st.expiresAt.UTC().Format(time.RFC3339)}
			return nil
		case status == http.StatusNotFound:
			return fail(CodeRoomNotFound, nil)
		case status == http.StatusConflict:
			return fail(CodeRoomFull, nil)
		default:
			return statusError(status)
		}
	})
	return result, err
}

// seat derives what a create or a join sends: the room keys, this account's card in the room
// and the code sealed for this account.
func (a *Agent) seat(code *e2e.RoomCode) (*e2e.Room, *e2e.RoomMember, string, error) {
	if err := a.requireIdentity(); err != nil {
		return nil, nil, "", err
	}
	keys, err := e2e.DeriveRoom(code.Secret)
	if err != nil {
		return nil, nil, "", fail(CodeInternal, err)
	}
	member, err := keys.Member(a.root)
	if err != nil {
		return nil, nil, "", fail(CodeInternal, err)
	}
	vault, err := e2e.SealVault(a.root, keys.ID, code)
	if err != nil {
		return nil, nil, "", fail(CodeInternal, err)
	}
	return keys, member, vault, nil
}

// settle verifies the room the server answered with, exactly as a listed one, and keeps it.
func (a *Agent) settle(conv *models.ConversationDTO, keys *e2e.Room) (*roomState, error) {
	if conv.ID != keys.ID.String() {
		return nil, fail(CodeServerAnswer, nil)
	}
	st, err := a.adopt(conv)
	if err != nil {
		return nil, err
	}
	a.rooms[st.id] = st
	return st, nil
}

// requireIdentity guards the derivations that need the rooms root.
func (a *Agent) requireIdentity() error {
	if len(a.root) == 0 {
		return fail(CodeIdentityMissing, nil)
	}
	return nil
}
