package store

import (
	"time"

	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// ---------- retired conversation ids ----------

// A conversation id is retired while a burned room's tombstone or an orphan names it: no
// conversation is created under it again. A tombstone keeps a burned room's code from opening a
// room again (its id derives from the code alone) until the room's own expiry; an orphan keeps a
// new conversation from reaching the deleted one's messages and file parts, which are keyed by
// the conversation id, until retention removed them.
const (
	colExpiresAt  = "expires_at"
	colOrphanedOn = "orphaned_on"
	day           = 24 * time.Hour
	sqlRetired    = "SELECT (SELECT count(*) FROM burned_rooms WHERE id = ?) + " +
		"(SELECT count(*) FROM orphaned_conversations WHERE id = ?)"
)

// utcDay is the UTC day of t (an orphan's date: nothing finer is kept).
func utcDay(t time.Time) time.Time {
	return t.UTC().Truncate(day)
}

// tombstoneRoom deletes a room's row and, when the room had not expired yet (a burn by its owner
// or by the owner's account deletion), leaves its tombstone: the id and the room's own expiry,
// nothing else. A conversation that is not a room deletes nothing here.
func tombstoneRoom(tx *gorm.DB, id uuid.UUID, now time.Time) error {
	var rooms []models.Room
	if err := tx.Clauses(clause.Returning{Columns: []clause.Column{{Name: colExpiresAt}}}).
		Where(whereID, id).Delete(&rooms).Error; err != nil {
		return err
	}
	if len(rooms) == 0 || !rooms[0].ExpiresAt.After(now) {
		return nil
	}
	return tx.Clauses(clause.OnConflict{DoNothing: true}).
		Create(&models.BurnedRoom{ID: id, ExpiresAt: rooms[0].ExpiresAt}).Error
}

// refuseRetiredID answers ErrConflict when id is retired. Creates call it after inserting their
// rows, in the same transaction: an insert that waited on a burn of the same id (the conversation
// row's unique key) sees, once that burn committed, the tombstone or orphan it left.
func refuseRetiredID(tx *gorm.DB, id uuid.UUID) error {
	var retired int64
	if err := tx.Raw(sqlRetired, id, id).Scan(&retired).Error; err != nil {
		return err
	}
	if retired > 0 {
		return ErrConflict
	}
	return nil
}
