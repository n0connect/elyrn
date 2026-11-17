package store

import (
	"elyrn/internal/models"

	"gorm.io/gorm/clause"
)

// ---------- users: encrypted conversation index ----------

// LockUsers loads and row-locks users in UUID order (a global order prevents deadlocks).
// Must run inside Transaction.
func (r *chatRepository) LockUsers(userUUIDs []string) (map[string]*models.User, error) {
	var users []models.User
	err := r.db().Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}).
		Where("uuid IN ?", userUUIDs).Order("uuid").Find(&users).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.LockUsers", err)
		return nil, err
	}
	result := make(map[string]*models.User, len(users))
	for i := range users {
		result[users[i].UUID] = &users[i]
	}
	return result, nil
}

func (r *chatRepository) SaveConvIndex(userUUID, enc string) error {
	result := r.db().Model(&models.User{}).Where(whereUUID, userUUID).UpdateColumn("conv_index_enc", enc)
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.SaveConvIndex", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteUser removes the account row (its credentials, keys and conversation index).
func (r *chatRepository) DeleteUser(userUUID string) error {
	result := r.db().Where(whereUUID, userUUID).Delete(&models.User{})
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteUser", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
