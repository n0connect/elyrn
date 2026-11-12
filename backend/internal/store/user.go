package store

import (
	"errors"

	"elyrn/internal/models"
	"elyrn/internal/utils"

	"gorm.io/gorm"
)

var userRepoLogger = utils.NewLogger("USER_REPOSITORY")

// UserRepository defines the interface for user data access
type UserRepository interface {
	FindByUUID(uuid string) (*models.User, error)
	FindByAccountLookup(lookup string) (*models.User, error)
	Create(user *models.User) error
	ExistsByAccountLookup(lookup string) (bool, error)
	BumpSessionEpoch(uuid string) error
}

// userRepository implements UserRepository
type userRepository struct {
	handle
}

// NewUserRepository creates a UserRepository for request paths (database.DB)
func NewUserRepository() UserRepository {
	return &userRepository{requestHandle}
}

// NewBackgroundUserRepository creates a UserRepository for background work (database.BackgroundDB)
func NewBackgroundUserRepository() UserRepository {
	return &userRepository{backgroundHandle}
}

// FindByUUID finds a user by UUID
func (r *userRepository) FindByUUID(uuid string) (*models.User, error) {
	var user models.User
	result := r.db().Where(whereUUID, uuid).First(&user)
	if result.Error != nil {
		// Not found is an expected outcome (unknown account, deleted user): not an error to log
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		userRepoLogger.LogError("UserRepository.FindByUUID", result.Error)
		return nil, result.Error
	}
	return &user, nil
}

// Create creates a new user; ErrConflict means the account lookup is already taken
func (r *userRepository) Create(user *models.User) error {
	err := r.db().Create(user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ErrConflict
		}
		userRepoLogger.LogError("UserRepository.Create", err)
		return err
	}
	return nil
}

// FindByAccountLookup finds a user by account lookup (HMAC)
func (r *userRepository) FindByAccountLookup(lookup string) (*models.User, error) {
	var user models.User
	result := r.db().Where(whereAccountLookup, lookup).First(&user)
	if result.Error != nil {
		// Not found is an expected outcome (unknown account, deleted user): not an error to log
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		userRepoLogger.LogError("UserRepository.FindByAccountLookup", result.Error)
		return nil, result.Error
	}
	return &user, nil
}

// ExistsByAccountLookup checks if a user exists with the given account lookup
func (r *userRepository) ExistsByAccountLookup(lookup string) (bool, error) {
	var count int64
	result := r.db().Model(&models.User{}).Where(whereAccountLookup, lookup).Count(&count)
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.ExistsByAccountLookup", result.Error)
		return false, result.Error
	}
	exists := count > 0
	return exists, nil
}

// BumpSessionEpoch invalidates every JWT issued to the user (logout = revoke all sessions)
func (r *userRepository) BumpSessionEpoch(uuid string) error {
	result := r.db().Model(&models.User{}).Where(whereUUID, uuid).
		UpdateColumn("session_epoch", gorm.Expr("session_epoch + 1"))
	if result.Error != nil {
		userRepoLogger.LogError("UserRepository.BumpSessionEpoch", result.Error)
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}
