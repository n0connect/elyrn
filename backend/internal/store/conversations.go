package store

import (
	"errors"
	"time"

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
		if err := tx.Create(&members).Error; err != nil {
			return err
		}
		return refuseRetiredID(tx, conversationID)
	})
	if errors.Is(err, ErrConflict) {
		return err
	}
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

// DeleteConversation ends a conversation for every member: what grants access goes in the
// caller's transaction, and the ciphertext is left to retention. A room's row goes first (lock
// order is rooms before conversations, LOCK_HIERARCHY.md), leaving its tombstone when it is
// burned before its expiry; the conversation row is locked next, so a send or upload holding
// that lock (NextSeq, LockConversation) commits first and one waiting for it then finds no
// conversation (ErrNotFound). Then the memberships, the notes and the conversation row go, and
// the conversation is queued as an orphan: its messages and file parts stay on disk, unreachable
// (every read needs the conversation's membership), until retention deletes them in bounded
// batches (purgeOrphans). Nothing here grows with the conversation's history, so no member can
// make a burn or an account deletion outlast its request. Burn, room expiry and account
// deletion all end here.
func (r *chatRepository) DeleteConversation(conversationID uuid.UUID, now time.Time) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tombstoneRoom(tx, conversationID, now); err != nil {
			return err
		}
		if _, err := (&chatRepository{handle: r.handle, tx: tx}).LockConversation(conversationID); err != nil {
			return err
		}
		if err := tx.Where(whereConversation, conversationID).Delete(&models.ConversationMember{}).Error; err != nil {
			return err
		}
		if err := tx.Where(whereConversation, conversationID).Delete(&models.RoomNote{}).Error; err != nil {
			return err
		}
		if err := tx.Where(whereID, conversationID).Delete(&models.Conversation{}).Error; err != nil {
			return err
		}
		return tx.Create(&models.OrphanedConversation{ID: conversationID, OrphanedOn: utcDay(now)}).Error
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		chatRepoLogger.LogError("ChatRepository.DeleteConversation", err)
	}
	return err
}
