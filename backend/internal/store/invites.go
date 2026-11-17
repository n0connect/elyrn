package store

import (
	"time"

	"elyrn/internal/models"

	"gorm.io/gorm/clause"
)

// ---------- invites ----------

func (r *chatRepository) CountActiveInvites(creatorTag string, now time.Time) (int64, error) {
	var count int64
	err := r.db().Model(&models.Invite{}).
		Where("creator_tag = ? AND expires_at > ?", creatorTag, now).Count(&count).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.CountActiveInvites", err)
	}
	return count, err
}

// DeleteExpiredInvites drops a creator's dead invites so they do not linger as metadata.
func (r *chatRepository) DeleteExpiredInvites(creatorTag string, now time.Time) error {
	err := r.db().Where("creator_tag = ? AND expires_at <= ?", creatorTag, now).Delete(&models.Invite{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteExpiredInvites", err)
	}
	return err
}

// DeleteInvites removes every invite of one creator, pending or expired.
func (r *chatRepository) DeleteInvites(creatorTag string) error {
	err := r.db().Where("creator_tag = ?", creatorTag).Delete(&models.Invite{}).Error
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.DeleteInvites", err)
	}
	return err
}

func (r *chatRepository) CreateInvite(invite *models.Invite) error {
	if err := r.db().Create(invite).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.CreateInvite", err)
		return err
	}
	return nil
}

// TakeInvite atomically deletes and returns an invite (single use, race-free).
// The creator can never consume their own invite: the row simply does not match.
func (r *chatRepository) TakeInvite(lookup, redeemerTag string, now time.Time) (*models.Invite, error) {
	var invite models.Invite
	result := r.db().Clauses(clause.Returning{}).
		Where("lookup = ? AND creator_tag <> ?", lookup, redeemerTag).Delete(&invite)
	if result.Error != nil {
		chatRepoLogger.LogError("ChatRepository.TakeInvite", result.Error)
		return nil, result.Error
	}
	if result.RowsAffected == 0 || !now.Before(invite.ExpiresAt) {
		return nil, ErrNotFound
	}
	return &invite, nil
}
