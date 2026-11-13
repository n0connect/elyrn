package chat

import (
	"errors"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/store"

	"github.com/google/uuid"
)

// ErrIDTaken: the client-generated id of a message or note is held by a record that is not the
// sender's own earlier attempt of this very send, so nothing was stored: send again under a
// fresh id. ErrConflict on a duplicate id keeps its one meaning, "your earlier attempt with this
// id is stored" (a resend after a lost answer).
var ErrIDTaken = errors.New("id taken")

// Telling the two duplicate answers apart adds no existence oracle. Both are 409 and both are
// reached only by a member of the conversation in the path: the membership check runs first, so
// a non-member gets the chat 404 before any id is looked at. Before the split, any duplicate id
// already answered 409, so "this id exists somewhere on the server" was already public to a
// member who sends with it (the id is unique server-wide; a fresh UUIDv4 never meets this).
// What the split adds is only whether the stored record is the caller's own: the same
// conversation, written under the caller's own member tag (the pseudonym only the caller's
// session resolves to), with byte for byte the content the caller sends now. Every one of those
// facts is about a send the caller itself made; a record of another member or of another
// conversation answers ErrIDTaken whatever it holds, exactly as any unknown duplicate did. The
// content is compared only once the record is known to be the caller's, and in constant time,
// so not even the time of the answer depends on another member's ciphertext.

// sameSend reports whether a stored record is the caller's own earlier attempt of this send:
// owned (same conversation and member tag, and for a note the same addressee) and byte-identical.
func sameSend(owned bool, stored, sent string) bool {
	return owned && cryptoengine.ConstantTimeEqual([]byte(stored), []byte(sent))
}

// duplicateAnswer is the answer to a send whose id a stored record already holds.
func duplicateAnswer(same bool) error {
	if same {
		return ErrConflict
	}
	return ErrIDTaken
}

// messageDuplicate answers a message send whose id may already be stored: nil when no message
// holds messageID, otherwise ErrConflict (the caller's own identical message in this
// conversation: the earlier attempt is stored) or ErrIDTaken (anything else).
func messageDuplicate(repo store.ChatRepository, messageID, conversationID uuid.UUID, senderTag, ciphertext string) error {
	existing, err := repo.FindMessage(messageID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return duplicateAnswer(sameSend(existing.ConversationID == conversationID && existing.SenderTag == senderTag,
		existing.Ciphertext, ciphertext))
}

// racedMessage answers a message insert the unique id refused although the check before it found
// no holder (a concurrent send of the same id won the race): the holder is looked up again, and a
// holder that is gone by now is never taken as stored.
func racedMessage(repo store.ChatRepository, messageID, conversationID uuid.UUID, senderTag, ciphertext string) error {
	if err := messageDuplicate(repo, messageID, conversationID, senderTag, ciphertext); err != nil {
		return err
	}
	return ErrIDTaken
}

// noteDuplicate answers a note insert the store refused (store.ErrConflict): either the note's id
// is held, or a note from this sender already waits for this addressee (the pair is unique). A
// note holding the id is judged like a message (sameSend, the addressee included); with no
// holder of the id, the pair refused it: ErrConflict, "a note from you already waits for them".
func noteDuplicate(repo store.ChatRepository, sent *models.RoomNote) error {
	existing, err := repo.FindNote(sent.ID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	owned := existing.ConversationID == sent.ConversationID && existing.SenderTag == sent.SenderTag &&
		existing.RecipientTag == sent.RecipientTag
	return duplicateAnswer(sameSend(owned, existing.Blob, sent.Blob))
}
