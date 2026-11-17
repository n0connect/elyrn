package store

import (
	"errors"
	"time"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// FileRepository is the data access for file parts (part of ChatRepository: an upload runs in
// the same transaction as the conversation lock it is serialised by).
type FileRepository interface {
	CreateFilePart(part *models.FilePart) error
	// FindFilePart is the part stored under (conversation, file, part), live or not
	FindFilePart(conversationID, fileID uuid.UUID, part int) (*models.FilePart, error)
	// FindFileStart is part 0 of a file, live on today, without its data: who opened the file
	FindFileStart(conversationID, fileID uuid.UUID, today time.Time) (*models.FilePart, error)
	// LiveFilePart is one part a member may read: stored and not past its deletion day
	LiveFilePart(conversationID, fileID uuid.UUID, part int, today time.Time) (*models.FilePart, error)
	// CountFileParts counts the parts stored in one conversation, live or not
	CountFileParts(conversationID uuid.UUID) (int64, error)
	// CountAllFileParts counts every part stored on the server
	CountAllFileParts() (int64, error)
}

// SQL fragments of the file queries, spelled exactly as the schema names its columns
const (
	whereFilePart       = "conversation_id = ? AND file_id = ? AND part = ?"
	whereFilePartLive   = whereFilePart + " AND " + whereMessageLive // the messages' own day rule
	colExpiresOn        = "expires_on"
	firstFilePart       = 0
	selectFilePartsMeta = "conversation_id, file_id, part, uploader_tag, expires_on" // every column but data
)

func (r *chatRepository) CreateFilePart(part *models.FilePart) error {
	if err := r.db().Create(part).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.CreateFilePart", err)
		return err
	}
	return nil
}

func (r *chatRepository) FindFilePart(conversationID, fileID uuid.UUID, part int) (*models.FilePart, error) {
	return first[models.FilePart](r.db(), "ChatRepository.FindFilePart", whereFilePart, conversationID, fileID, part)
}

func (r *chatRepository) FindFileStart(conversationID, fileID uuid.UUID, today time.Time) (*models.FilePart, error) {
	return first[models.FilePart](r.db().Select(selectFilePartsMeta), "ChatRepository.FindFileStart",
		whereFilePartLive, conversationID, fileID, firstFilePart, today)
}

func (r *chatRepository) LiveFilePart(conversationID, fileID uuid.UUID, part int, today time.Time) (*models.FilePart, error) {
	return first[models.FilePart](r.db(), "ChatRepository.LiveFilePart", whereFilePartLive, conversationID, fileID, part, today)
}

func (r *chatRepository) CountFileParts(conversationID uuid.UUID) (int64, error) {
	var count int64
	if err := r.db().Model(&models.FilePart{}).Where(whereConversation, conversationID).Count(&count).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.CountFileParts", err)
		return 0, err
	}
	return count, nil
}

func (r *chatRepository) CountAllFileParts() (int64, error) {
	var count int64
	if err := r.db().Model(&models.FilePart{}).Count(&count).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.CountAllFileParts", err)
		return 0, err
	}
	return count, nil
}

// capFileParts keeps no part past latest, as the cap step does for messages (a lowered
// MESSAGE_TTL_DAYS shortens what is already stored).
func (r *chatRepository) capFileParts(latest time.Time) error {
	_, err := r.bulk("file parts cap", func(tx *gorm.DB) *gorm.DB {
		return tx.Model(&models.FilePart{}).Where(colExpiresOn+" > ?", latest).UpdateColumn(colExpiresOn, latest)
	})
	return err
}

// purgeFileParts deletes the parts past their deletion day, by the messages' own rule.
func (r *chatRepository) purgeFileParts(today time.Time) (int64, error) {
	return r.bulk("file parts", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereMessageExpired, today).Delete(&models.FilePart{})
	})
}
