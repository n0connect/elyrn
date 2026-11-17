package chat

import (
	"errors"
	"time"

	"elyrn/internal/auth"
	"elyrn/internal/models"
	"elyrn/internal/store"

	"github.com/google/uuid"
)

// ---------- conversations ----------

// ListConversations returns the caller's conversations in index order (newest first).
// Recency across conversations is deliberately not tracked server-side.
func (s *Service) ListConversations(me *Member) ([]models.ConversationDTO, error) {
	user, err := s.users.FindByUUID(me.UserUUID)
	if err != nil {
		return nil, err
	}
	ids, err := openIndex(me, user.ConvIndexEnc)
	if err != nil {
		return nil, err
	}

	tags := make([]string, len(ids))
	for i, id := range ids {
		if tags[i], err = me.tag(id); err != nil {
			return nil, err
		}
	}
	memberships, err := s.chats.FindMembershipsByTags(tags)
	if err != nil {
		return nil, err
	}
	lastSeqs, err := s.chats.LastSeqs(ids)
	if err != nil {
		return nil, err
	}
	rooms, counts, notes, err := s.roomDetails(ids, tags)
	if err != nil {
		return nil, err
	}

	result := make([]models.ConversationDTO, 0, len(ids))
	stale := make(map[uuid.UUID]struct{})
	now := time.Now()
	for i, id := range ids {
		member, ok := memberships[id]
		if !ok || member.MemberTag != tags[i] {
			stale[id] = struct{}{}
			continue
		}
		if room, isRoom := rooms[id]; isRoom {
			if !roomAlive(&room, now) {
				stale[id] = struct{}{}
				continue
			}
			result = append(result, roomDTO(&room, &member, counts[id], notes[id], lastSeqs[id]))
			continue
		}
		peerKey, err := s.openPeerKey(me, &member)
		if err != nil {
			s.logger.Error("SECURITY: a stored peer key failed authentication")
			continue
		}
		result = append(result, models.ConversationDTO{
			ID:            id.String(),
			PeerPublicKey: peerKey,
			LastSeq:       lastSeqs[id],
			ReadSeq:       member.ReadSeq,
		})
	}
	if len(stale) > 0 {
		s.pruneIndex(me, stale)
	}
	return result, nil
}

// roomDetails loads, for the rooms among ids, the room rows, member counts and the caller's
// waiting notes (tags are the caller's per-conversation tags, in the order of ids).
func (s *Service) roomDetails(ids []uuid.UUID, tags []string) (map[uuid.UUID]models.Room, map[uuid.UUID]int, map[uuid.UUID]int, error) {
	rooms, err := s.chats.FindRooms(ids)
	if err != nil || len(rooms) == 0 {
		return rooms, nil, nil, err
	}
	roomIDs := make([]uuid.UUID, 0, len(rooms))
	roomTags := make([]string, 0, len(rooms))
	for i, id := range ids {
		if _, isRoom := rooms[id]; isRoom {
			roomIDs = append(roomIDs, id)
			roomTags = append(roomTags, tags[i])
		}
	}
	counts, err := s.chats.CountMembers(roomIDs)
	if err != nil {
		return nil, nil, nil, err
	}
	notes, err := s.chats.CountNotesFor(roomTags, time.Now().UTC())
	if err != nil {
		return nil, nil, nil, err
	}
	return rooms, counts, notes, nil
}

// pruneIndex drops ids whose conversation no longer exists (burned by the peer elsewhere).
func (s *Service) pruneIndex(me *Member, stale map[uuid.UUID]struct{}) {
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil || rows[me.UserUUID] == nil {
			return err
		}
		ids, err := openIndex(me, rows[me.UserUUID].ConvIndexEnc)
		if err != nil {
			return err
		}
		return s.saveIndex(tx, me, withoutID(ids, stale))
	})
	if err != nil {
		s.logger.LogError("pruneIndex", err)
	}
}

// BurnConversation deletes a conversation and all its ciphertext for every member,
// and removes it from every member's encrypted index. In a room only the owner burns;
// any other member leaves instead.
func (s *Service) BurnConversation(me *Member, conversationID uuid.UUID) ([]string, error) {
	room, err := s.liveRoom(s.chats, conversationID)
	if err != nil {
		return nil, err
	}
	if room != nil {
		tag, err := me.tag(conversationID)
		if err != nil {
			return nil, err
		}
		if tag != room.OwnerTag {
			return s.leaveRoom(me, conversationID)
		}
	}
	var streams []string
	var parts int64
	since := s.partsMark()
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := s.requireMembership(tx, me, conversationID); err != nil {
			return err
		}
		uuids, peerStreams, err := s.peerStreams(tx, me, conversationID)
		if err != nil {
			return err
		}
		rows, err := tx.LockUsers(uuids)
		if err != nil {
			return err
		}
		if parts, err = tx.DeleteConversation(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		drop := map[uuid.UUID]struct{}{conversationID: {}}
		for _, row := range rows {
			member, err := memberFromUser(row)
			if err != nil {
				return err
			}
			ids, err := openIndex(member, row.ConvIndexEnc)
			if err != nil {
				return err
			}
			if err := s.saveIndex(tx, member, withoutID(ids, drop)); err != nil {
				return err
			}
		}
		streams = peerStreams
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.partsRemoved(parts, since)
	s.logger.Debug("BurnConversation: conversation burned")
	return streams, nil
}

// DeleteAccount erases the caller once authKey proves the account: its invites, every
// conversation it is in (all ciphertext, for both sides; rooms it owns likewise, rooms it
// joined it only leaves) and the account row. Returns the
// peers' live-event addresses. The key is checked against the locked row that is deleted; the
// lookup is HMAC(pepper, auth key), so a match proves the key without an Argon2 run.
// Lock order is RedeemInvite's (invites, then users), so the invites go first; a wrong key
// rolls the whole transaction back. Peers' rows are left unlocked: their encrypted indexes
// drop the vanished conversations at their next listing (pruneIndex).
func (s *Service) DeleteAccount(me *Member, authKey string) ([]string, error) {
	lookup, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		return nil, err
	}
	var streams []string
	var parts int64
	since := s.partsMark()
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if err := tx.DeleteInvites(me.inviteTag); err != nil {
			return err
		}
		rows, err := tx.LockUsers([]string{me.UserUUID})
		if err != nil {
			return err
		}
		row := rows[me.UserUUID]
		if row == nil {
			return ErrNotFound
		}
		if !auth.AccountLookupMatches(lookup, row.AccountLookup) {
			return ErrForbidden
		}
		ids, err := openIndex(me, row.ConvIndexEnc)
		if err != nil {
			return err
		}
		for _, id := range ids {
			member, err := s.requireMembership(tx, me, id)
			if errors.Is(err, ErrNotFound) {
				continue // the peer burned it already
			} else if err != nil {
				return err
			}
			_, peers, err := s.peerStreams(tx, me, id)
			if err != nil {
				return err
			}
			removed, err := s.forget(tx, id, member)
			if err != nil {
				return err
			}
			parts += removed
			streams = append(streams, peers...)
		}
		if err := tx.DeleteUser(me.UserUUID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.partsRemoved(parts, since)
	s.logger.Debug("DeleteAccount: account erased")
	return streams, nil
}

// forget removes one of a deleted account's conversations: a room it joined loses only its
// membership (taken under the conversation lock, as leaving does; its file parts stay with its
// messages), anything else is burned. Returns the file parts removed.
func (s *Service) forget(tx store.ChatRepository, id uuid.UUID, member *models.ConversationMember) (int64, error) {
	room, err := tx.FindRoom(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	if room != nil && room.OwnerTag != member.MemberTag {
		if _, err := tx.LockConversation(id); err != nil {
			return 0, err
		}
		return 0, tx.DeleteMember(id, member.MemberTag)
	}
	parts, err := tx.DeleteConversation(id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return 0, err
	}
	return parts, nil
}
