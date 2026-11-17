package store

import (
	"errors"
	"time"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ---------- room notes ----------

// CreateNote stores a note; an expired note between the same two members makes way for it.
func (r *chatRepository) CreateNote(note *models.RoomNote) error {
	err := r.db().Where("conversation_id = ? AND sender_tag = ? AND recipient_tag = ? AND expires_at <= ?",
		note.ConversationID, note.SenderTag, note.RecipientTag, time.Now().UTC()).Delete(&models.RoomNote{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateNote (expired)", err)
		return err
	}
	if err := r.db().Create(note).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.CreateNote", err)
		return err
	}
	return nil
}

func (r *chatRepository) FindNote(noteID uuid.UUID) (*models.RoomNote, error) {
	return first[models.RoomNote](r.db(), "ChatRepository.FindNote", whereID, noteID)
}

// CountNotesFor counts live notes per room for the caller's per-room tags.
func (r *chatRepository) CountNotesFor(recipientTags []string, now time.Time) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(recipientTags))
	if len(recipientTags) == 0 {
		return result, nil
	}
	var rows []struct {
		ConversationID uuid.UUID
		Count          int
	}
	err := r.db().Model(&models.RoomNote{}).Select(selectCountPerConversation).
		Where("recipient_tag IN ? AND expires_at > ?", recipientTags, now).Group(colConversationID).Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountNotesFor", err)
		return nil, err
	}
	for _, row := range rows {
		result[row.ConversationID] = row.Count
	}
	return result, nil
}

func (r *chatRepository) ListNotes(conversationID uuid.UUID, recipientTag string, now time.Time) ([]models.RoomNote, error) {
	var notes []models.RoomNote
	err := r.db().Where("conversation_id = ? AND recipient_tag = ? AND expires_at > ?", conversationID, recipientTag, now).
		Order(colID).Find(&notes).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListNotes", err)
	}
	return notes, err
}

// DeleteNote removes a note addressed to recipientTag; nobody else can delete it.
func (r *chatRepository) DeleteNote(conversationID, noteID uuid.UUID, recipientTag string) error {
	result := r.db().Where("id = ? AND conversation_id = ? AND recipient_tag = ?", noteID, conversationID, recipientTag).
		Delete(&models.RoomNote{})
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteNote", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
