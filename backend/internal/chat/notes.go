package chat

import (
	"errors"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// ---------- notes ----------

// SendNote delivers a sealed note (a friend request) to the one member whose card is `to`.
// At most one note waits per sender and addressee, so a member never has more waiting than
// the room has other members. The note's header card must be the sender's stored card
// (checkSenderCard). Returns the addressee's live-event address.
func (s *Service) SendNote(me *Member, id uuid.UUID, rawNoteID, to, blob string) (string, error) {
	noteID, okID := utils.ParseCanonicalUUIDv4(rawNoteID)
	_, okTo := utils.DecodeExact(to, utils.RoomCardBytes)
	parsed, okBlob := utils.ParseRoomBlob(blob, utils.RoomNoteMagic, noteWraps)
	if !okID || !okTo || !okBlob {
		return "", ErrInvalidInput
	}
	// A note's digest covers exactly its addressee's card
	digest, err := rosterDigest([]string{to})
	if err != nil {
		return "", err
	}
	if !cryptoengine.ConstantTimeEqual(digest, parsed.Digest) {
		return "", ErrInvalidInput
	}
	room, err := s.requireRoom(s.chats, id)
	if err != nil {
		return "", err
	}
	var stream string
	var refused *models.RoomNote
	err = s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := tx.LockConversation(id); err != nil {
			return err
		}
		sender, err := s.requireMembership(tx, me, id)
		if err != nil {
			return err
		}
		members, err := tx.ListMembers(id)
		if err != nil {
			return err
		}
		recipient := memberWithCard(members, to)
		if recipient == nil {
			return ErrNotFound
		}
		if recipient.MemberTag == sender.MemberTag {
			return ErrInvalidInput
		}
		// Judged last, as for a message: every earlier answer keeps its order
		if err := checkSenderCard(sender, parsed); err != nil {
			return err
		}
		// On the hour like the room's own expiry (expiryAfter), and never after the room
		expiresAt := expiryAfter(time.Now(), config.GetInviteTTL())
		if room.ExpiresAt.Before(expiresAt) {
			expiresAt = room.ExpiresAt
		}
		note := models.RoomNote{ID: noteID, ConversationID: id, SenderTag: sender.MemberTag, RecipientTag: recipient.MemberTag, Blob: blob, ExpiresAt: expiresAt}
		if err := tx.CreateNote(&note); err != nil {
			if errors.Is(err, store.ErrConflict) {
				refused = &note
			}
			return err
		}
		stream, err = memberStream(recipient)
		return err
	})
	if refused != nil {
		// The refused insert aborted the transaction: the holder is read outside it, and only
		// after membership and the addressee were checked (duplicates.go: no existence oracle)
		return "", noteDuplicate(s.chats, refused)
	}
	if err != nil {
		return "", err
	}
	s.logger.Debug("SendNote: note delivered")
	return stream, nil
}

// ListNotes returns the live notes addressed to the caller in one room.
func (s *Service) ListNotes(me *Member, id uuid.UUID) ([]models.NoteDTO, error) {
	if _, err := s.requireRoom(s.chats, id); err != nil {
		return nil, err
	}
	member, err := s.requireMembership(s.chats, me, id)
	if err != nil {
		return nil, err
	}
	notes, err := s.chats.ListNotes(id, member.MemberTag, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	result := make([]models.NoteDTO, len(notes))
	for i, n := range notes {
		result[i] = models.NoteDTO{ID: n.ID.String(), Blob: n.Blob}
	}
	return result, nil
}

// DeleteNote removes a note addressed to the caller (accepted or ignored).
func (s *Service) DeleteNote(me *Member, id, noteID uuid.UUID) error {
	if _, err := s.requireRoom(s.chats, id); err != nil {
		return err
	}
	member, err := s.requireMembership(s.chats, me, id)
	if err != nil {
		return err
	}
	if err := s.chats.DeleteNote(id, noteID, member.MemberTag); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNotFound
		}
		return err
	}
	return nil
}
