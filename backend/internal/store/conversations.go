package store

import (
	"errors"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ---------- conversations ----------

func (r *chatRepository) CreateConversation(conversationID uuid.UUID, members []models.ConversationMember) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&models.Conversation{ID: conversationID}).Error; err != nil {
			return err
		}
		return tx.Create(&members).Error
	})
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateConversation", err)
	}
	return err
}

func (r *chatRepository) FindMembership(conversationID uuid.UUID, memberTag string) (*models.ConversationMember, error) {
	return first[models.ConversationMember](r.db(), "ChatRepository.FindMembership", whereMember, conversationID, memberTag)
}

// FindMembershipsByTags resolves many per-conversation tags in one query.
func (r *chatRepository) FindMembershipsByTags(memberTags []string) (map[uuid.UUID]models.ConversationMember, error) {
	result := make(map[uuid.UUID]models.ConversationMember, len(memberTags))
	if len(memberTags) == 0 {
		return result, nil
	}
	var members []models.ConversationMember
	if err := r.db().Where("member_tag IN ?", memberTags).Find(&members).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.FindMembershipsByTags", err)
		return nil, err
	}
	for _, m := range members {
		result[m.ConversationID] = m
	}
	return result, nil
}

func (r *chatRepository) ListMembers(conversationID uuid.UUID) ([]models.ConversationMember, error) {
	var members []models.ConversationMember
	err := r.db().Where(whereConversation, conversationID).Find(&members).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.ListMembers", err)
	}
	return members, err
}

func (r *chatRepository) LastSeqs(conversationIDs []uuid.UUID) (map[uuid.UUID]int64, error) {
	result := make(map[uuid.UUID]int64, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	var conversations []models.Conversation
	if err := r.db().Where(whereIDIn, conversationIDs).Find(&conversations).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LastSeqs", err)
		return nil, err
	}
	for _, c := range conversations {
		result[c.ID] = c.LastSeq
	}
	return result, nil
}

// DeleteConversation burns a conversation for every member, ciphertext included. A room's row
// goes first: lock order is rooms before conversations (LOCK_HIERARCHY.md). The conversation row
// is locked next, before any row in it is deleted: a send holding that lock (NextSeq) commits
// first and its message is deleted here; a send waiting for it then finds no conversation
// (ErrNotFound). Deleting the messages first would miss one committed in between and leave its
// ciphertext behind with no conversation. Burn, room expiry and account deletion all end here.
// File parts go with the messages, under the same lock (an upload holds it too).
func (r *chatRepository) DeleteConversation(conversationID uuid.UUID) (int64, error) {
	var parts int64
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where(whereID, conversationID).Delete(&models.Room{}).Error; err != nil {
			return err
		}
		if _, err := (&chatRepository{handle: r.handle, tx: tx}).LockConversation(conversationID); err != nil {
			return err
		}
		if err := tx.Where(whereConversation, conversationID).Delete(&models.Message{}).Error; err != nil {
			return err
		}
		result := tx.Where(whereConversation, conversationID).Delete(&models.FilePart{})
		if result.Error != nil {
			return result.Error
		}
		parts = result.RowsAffected
		if err := tx.Where(whereConversation, conversationID).Delete(&models.ConversationMember{}).Error; err != nil {
			return err
		}
		if err := tx.Where(whereConversation, conversationID).Delete(&models.RoomNote{}).Error; err != nil {
			return err
		}
		return tx.Where(whereID, conversationID).Delete(&models.Conversation{}).Error
	})
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			chatRepoLogger.LogError("ChatRepository.DeleteConversation", err)
		}
		return 0, err
	}
	return parts, nil
}
