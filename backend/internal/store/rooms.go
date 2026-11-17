package store

import (
	"errors"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ---------- rooms ----------

// CreateRoom stores a new room, its conversation and its creator's membership together.
func (r *chatRepository) CreateRoom(room *models.Room, creator *models.ConversationMember) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&models.Conversation{ID: room.ID}).Error; err != nil {
			return err
		}
		if err := tx.Create(room).Error; err != nil {
			return err
		}
		return tx.Create(creator).Error
	})
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrConflict
	}
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateRoom", err)
	}
	return err
}

func (r *chatRepository) FindRoom(roomID uuid.UUID) (*models.Room, error) {
	return first[models.Room](r.db(), "ChatRepository.FindRoom", whereID, roomID)
}

// FindRooms returns the rooms among roomIDs (one-to-one conversations are simply absent).
func (r *chatRepository) FindRooms(roomIDs []uuid.UUID) (map[uuid.UUID]models.Room, error) {
	result := make(map[uuid.UUID]models.Room, len(roomIDs))
	if len(roomIDs) == 0 {
		return result, nil
	}
	var rooms []models.Room
	if err := r.db().Where(whereIDIn, roomIDs).Find(&rooms).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.FindRooms", err)
		return nil, err
	}
	for _, room := range rooms {
		result[room.ID] = room
	}
	return result, nil
}

// LockRoom loads and row-locks a room; joins of one room are serialised by it. Must run
// inside Transaction, after any users row lock and before the conversation row lock.
func (r *chatRepository) LockRoom(roomID uuid.UUID) (*models.Room, error) {
	var rooms []models.Room
	if err := r.db().Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).Where(whereID, roomID).Find(&rooms).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LockRoom", err)
		return nil, err
	}
	if len(rooms) != 1 {
		return nil, ErrNotFound
	}
	return &rooms[0], nil
}

// LockConversation row-locks a conversation and returns its last sequence number. Joins,
// leaves and sends all take this lock, so a message is checked against the roster it is
// stored under.
func (r *chatRepository) LockConversation(conversationID uuid.UUID) (int64, error) {
	var conversations []models.Conversation
	if err := r.db().Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).Where(whereID, conversationID).Find(&conversations).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.LockConversation", err)
		return 0, err
	}
	if len(conversations) != 1 {
		return 0, ErrNotFound
	}
	return conversations[0].LastSeq, nil
}

func (r *chatRepository) AddMember(member *models.ConversationMember) error {
	if err := r.db().Create(member).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		chatRepoLogger.LogError("ChatRepository.AddMember", err)
		return err
	}
	return nil
}

func (r *chatRepository) UpdateVault(conversationID uuid.UUID, memberTag, vault string) error {
	err := r.db().Model(&models.ConversationMember{}).
		Where(whereMember, conversationID, memberTag).UpdateColumn("vault", vault).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.UpdateVault", err)
	}
	return err
}

// UpdateRole replaces one member's sealed role; ErrNotFound when the membership is gone.
func (r *chatRepository) UpdateRole(conversationID uuid.UUID, memberTag, role string) error {
	result := r.db().Model(&models.ConversationMember{}).
		Where(whereMember, conversationID, memberTag).UpdateColumn("role", role)
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.UpdateRole", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteMember removes one membership and every note to or from it in that room.
func (r *chatRepository) DeleteMember(conversationID uuid.UUID, memberTag string) error {
	err := r.db().Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("conversation_id = ? AND (sender_tag = ? OR recipient_tag = ?)", conversationID, memberTag, memberTag).
			Delete(&models.RoomNote{}).Error; err != nil {
			return err
		}
		result := tx.Where(whereMember, conversationID, memberTag).Delete(&models.ConversationMember{})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		chatRepoLogger.LogError("ChatRepository.DeleteMember", err)
	}
	return err
}

func (r *chatRepository) CountMembers(conversationIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	result := make(map[uuid.UUID]int, len(conversationIDs))
	if len(conversationIDs) == 0 {
		return result, nil
	}
	var rows []struct {
		ConversationID uuid.UUID
		Count          int
	}
	err := r.db().Model(&models.ConversationMember{}).Select(selectCountPerConversation).
		Where("conversation_id IN ?", conversationIDs).Group(colConversationID).Scan(&rows).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountMembers", err)
		return nil, err
	}
	for _, row := range rows {
		result[row.ConversationID] = row.Count
	}
	return result, nil
}
