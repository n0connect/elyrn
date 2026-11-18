package chat

import (
	"errors"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// ---------- messages ----------

// PageCursor names which page of messages a read asks for.
type PageCursor struct {
	Kind CursorKind
	Seq  int64 // the cursor's seq; unused for CursorLatest
}

// CursorKind is the page a read asks for (the whitelisted query parameters of the messages route).
type CursorKind int

const (
	CursorLatest CursorKind = iota // the newest page
	CursorAfter                    // the oldest page above Seq: catching up
	CursorBefore                   // the newest page below Seq: paging back through history
)

// messageWindow turns a cursor into the stored range it reads. A room member never gets what was
// sent before they joined (it was not encrypted for them), so every window stops at joined_seq.
func messageWindow(cursor PageCursor, joinedSeq int64, limit int) store.MessageWindow {
	switch cursor.Kind {
	case CursorAfter:
		return store.MessageWindow{Floor: max(cursor.Seq, joinedSeq), Limit: limit}
	case CursorBefore:
		// A ceiling of FirstSeq is an empty page; 0 would mean "no ceiling"
		return store.MessageWindow{Floor: joinedSeq, Ceiling: max(cursor.Seq, FirstSeq), Newest: true, Limit: limit}
	default:
		return store.MessageWindow{Floor: joinedSeq, Newest: true, Limit: limit}
	}
}

// ListMessages returns the page of messages the cursor names, in ascending seq.
func (s *Service) ListMessages(me *Member, conversationID uuid.UUID, cursor PageCursor) ([]models.MessageDTO, error) {
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return nil, err
	}
	if _, err := s.liveRoom(s.chats, conversationID); err != nil {
		return nil, err
	}
	window := messageWindow(cursor, member.JoinedSeq, config.GetMessagePageLimit())
	messages, err := s.chats.ListMessages(conversationID, window, deletionCutoff(time.Now()))
	if err != nil {
		return nil, err
	}
	result := make([]models.MessageDTO, 0, len(messages))
	for _, m := range messages {
		result = append(result, models.MessageDTO{
			ID:         m.ID.String(),
			Seq:        m.Seq,
			Mine:       m.SenderTag == member.MemberTag,
			Ciphertext: m.Ciphertext,
		})
	}
	return result, nil
}

// expiryGranularity: invites and room notes expire on a whole hour, rounded up (rooms expire on
// whole hours, messages on whole days), so a stored expiry never tells the second a row was
// created. Rows stored before this keep their exact expiry and expire as stored.
const expiryGranularity = time.Hour

// expiryAfter is now + ttl rounded up to the next whole expiryGranularity (UTC): never before
// now + ttl, so an invite or a note lives at least its TTL, and at most one granule longer.
func expiryAfter(now time.Time, ttl time.Duration) time.Time {
	at := now.UTC().Add(ttl)
	rounded := at.Truncate(expiryGranularity)
	if rounded.Before(at) {
		rounded = rounded.Add(expiryGranularity)
	}
	return rounded
}

// expiryDay returns the day-granular deletion date for ciphertext stored now.
func expiryDay(now time.Time) time.Time {
	return deletionCutoff(now).Add(time.Duration(config.GetMessageTTLDays()) * day)
}

// deletionCutoff is the first deletion day still alive at now: a message whose deletion day is
// before it is expired, deleted by retention and never served before that (one rule for both).
func deletionCutoff(now time.Time) time.Time {
	return now.UTC().Truncate(day)
}

// SendMessage stores one opaque ciphertext under the conversation's next sequence number.
// A room message must have the room format and be encrypted for the current roster.
func (s *Service) SendMessage(me *Member, conversationID uuid.UUID, rawID, ciphertext string) (int64, []string, error) {
	messageID, ok := utils.ParseCanonicalUUIDv4(rawID)
	if !ok {
		return 0, nil, ErrInvalidInput
	}
	room, err := s.liveRoom(s.chats, conversationID)
	if err != nil {
		return 0, nil, err
	}
	var seq int64
	var senderTag string
	raced := false
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		// Membership first: the format a conversation expects (pair or room, and a room's size)
		// is told only to its members, so "not yours" answers exactly like "does not exist"; a
		// duplicate id is judged only after it too (duplicates.go: no existence oracle)
		member, err := s.requireMembership(tx, me, conversationID)
		if err != nil {
			return err
		}
		senderTag = member.MemberTag
		blob, err := messageBlob(room, ciphertext)
		if err != nil {
			return err
		}
		// A held id is judged before the roster: a resend after a lost answer whose first attempt
		// is stored answers "stored" (409) even when someone joined or left meanwhile, instead of
		// 412, which would make the client re-encrypt and resend different bytes under that id
		if err := messageDuplicate(tx, messageID, conversationID, senderTag, ciphertext); err != nil {
			return err
		}
		if seq, err = tx.NextSeq(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		if blob != nil {
			if err := checkRoomMessage(tx, conversationID, member, blob); err != nil {
				return err
			}
		}
		err = tx.CreateMessage(&models.Message{
			ConversationID: conversationID,
			Seq:            seq,
			ID:             messageID,
			SenderTag:      member.MemberTag,
			Ciphertext:     ciphertext,
			ExpiresOn:      expiryDay(time.Now()),
		})
		raced = errors.Is(err, store.ErrConflict)
		return err
	})
	if raced {
		// The refused insert aborted the transaction: the holder is read outside it
		return 0, nil, racedMessage(s.chats, messageID, conversationID, senderTag, ciphertext)
	}
	if err != nil {
		return 0, nil, err
	}
	_, streams, err := s.peerStreams(s.chats, me, conversationID)
	if err != nil {
		// The message is stored; the peer sees it on its next sync
		s.logger.LogError("peerStreams", err)
		return seq, nil, nil
	}
	return seq, streams, nil
}

// messageBlob checks a ciphertext against the format of its conversation: the room format with
// at most one wrap per seat in a room (returned parsed, for checkRoomMessage), the one-to-one
// format elsewhere (nil).
func messageBlob(room *models.Room, ciphertext string) (*utils.RoomBlob, error) {
	if room == nil {
		if !utils.ValidateCiphertext(ciphertext) {
			return nil, ErrInvalidInput
		}
		return nil, nil
	}
	blob, ok := utils.ParseRoomBlob(ciphertext, utils.RoomMessageMagic, room.MaxMembers)
	if !ok {
		return nil, ErrInvalidInput
	}
	return blob, nil
}

// MarkRead advances the caller's read marker (never backwards, never past the end). seq is at
// least FirstSeq: the input contract refuses anything lower before a handler runs.
func (s *Service) MarkRead(me *Member, conversationID uuid.UUID, seq int64) error {
	member, err := s.requireMembership(s.chats, me, conversationID)
	if err != nil {
		return err
	}
	lastSeqs, err := s.chats.LastSeqs([]uuid.UUID{conversationID})
	if err != nil {
		return err
	}
	if seq > lastSeqs[conversationID] {
		return ErrInvalidInput
	}
	return s.chats.AdvanceReadSeq(conversationID, member.MemberTag, seq)
}
