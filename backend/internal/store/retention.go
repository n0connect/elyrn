package store

import (
	"errors"
	"time"

	"elyrn/internal/database"
	"elyrn/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ---------- retention ----------

// PurgeExpired deletes ciphertext (messages and file parts) past its deletion day, invites and
// notes past expiry, and
// expired rooms with everything in them. Nothing is kept past latest either: a lowered
// MESSAGE_TTL_DAYS also shortens what is already stored. Every step runs on its own, so one that
// fails (and is logged) does not starve the others; their errors come back joined.
func (r *chatRepository) PurgeExpired(today, latest, now time.Time) (PurgeCounts, error) {
	var counts PurgeCounts
	_, capErr := r.bulk("cap", func(tx *gorm.DB) *gorm.DB {
		return tx.Model(&models.Message{}).Where("expires_on > ?", latest).UpdateColumn("expires_on", latest)
	})
	partsCapErr := r.capFileParts(latest)
	var messagesErr, partsErr, invitesErr, notesErr error
	counts.Messages, messagesErr = r.bulk("messages", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereMessageExpired, today).Delete(&models.Message{})
	})
	counts.FileParts, partsErr = r.purgeFileParts(today)
	counts.Invites, invitesErr = r.bulk("invites", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereExpired, now).Delete(&models.Invite{})
	})
	counts.Notes, notesErr = r.bulk("notes", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereExpired, now).Delete(&models.RoomNote{})
	})
	var roomsErr error
	var roomParts int64
	counts.Rooms, roomParts, roomsErr = r.purgeRooms(now)
	counts.FileParts += roomParts
	return counts, errors.Join(capErr, partsCapErr, messagesErr, partsErr, invitesErr, notesErr, roomsErr)
}

// bulk runs one retention statement in its own transaction, allowed the longer retention
// statement timeout, and logs its failure under the step's name.
func (r *chatRepository) bulk(step string, statement func(tx *gorm.DB) *gorm.DB) (int64, error) {
	var affected int64
	err := database.LongTransaction(r.db(), database.RetentionStatementTimeout, func(tx *gorm.DB) error {
		result := statement(tx)
		affected = result.RowsAffected
		return result.Error
	})
	if err != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired ("+step+")", err)
	}
	return affected, err
}

// purgeRooms burns up to roomPurgeBatch expired rooms, each on its own: one that fails is
// retried next pass and does not keep the others. Returns the rooms and file parts removed.
func (r *chatRepository) purgeRooms(now time.Time) (int64, int64, error) {
	var expired []uuid.UUID
	if err := r.db().Model(&models.Room{}).Where(whereExpired, now).Limit(roomPurgeBatch).Pluck(colID, &expired).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (rooms)", err)
		return 0, 0, err
	}
	var purged, parts int64
	var errs []error
	for _, id := range expired {
		removed, err := r.DeleteConversation(id)
		if err != nil && !errors.Is(err, ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		purged++
		parts += removed
	}
	return purged, parts, errors.Join(errs...)
}
