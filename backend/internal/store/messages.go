package store

import (
	"errors"
	"time"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ---------- messages ----------

// NextSeq bumps the conversation's own counter; the row lock it takes serialises
// concurrent senders until the surrounding transaction ends.
func (r *chatRepository) NextSeq(conversationID uuid.UUID) (int64, error) {
	var rows []struct{ LastSeq int64 }
	err := r.db().Raw("UPDATE conversations SET last_seq = last_seq + 1 WHERE id = ? RETURNING last_seq", conversationID).
		Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.NextSeq", err)
		return 0, err
	}
	if len(rows) != 1 {
		return 0, ErrNotFound
	}
	return rows[0].LastSeq, nil
}

func (r *chatRepository) CreateMessage(message *models.Message) error {
	err := r.db().Create(message).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.CreateMessage", err)
	}
	return err
}

func (r *chatRepository) FindMessage(messageID uuid.UUID) (*models.Message, error) {
	return first[models.Message](r.db(), "ChatRepository.FindMessage", whereID, messageID)
}

// ListMessages is the one query behind every message page (MessageWindow). A message past its
// deletion day (expires_on before today, exactly what PurgeExpired deletes) is never served,
// whether or not retention has run yet.
func (r *chatRepository) ListMessages(conversationID uuid.UUID, window MessageWindow, today time.Time) ([]models.Message, error) {
	query := r.db().Where("conversation_id = ? AND seq > ? AND "+whereMessageLive, conversationID, window.Floor, today)
	if window.Ceiling > 0 {
		query = query.Where("seq < ?", window.Ceiling)
	}
	order := "seq ASC"
	if window.Newest {
		order = "seq DESC"
	}
	var messages []models.Message
	if err := query.Order(order).Limit(window.Limit).Find(&messages).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMessages", err)
		return nil, err
	}
	if window.Newest {
		for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
			messages[i], messages[j] = messages[j], messages[i]
		}
	}
	return messages, nil
}

// AdvanceReadSeq only moves the read marker forward.
func (r *chatRepository) AdvanceReadSeq(conversationID uuid.UUID, memberTag string, seq int64) error {
	err := r.db().Model(&models.ConversationMember{}).
		Where("conversation_id = ? AND member_tag = ? AND read_seq < ?", conversationID, memberTag, seq).
		UpdateColumn("read_seq", seq).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.AdvanceReadSeq", err)
	}
	return err
}
