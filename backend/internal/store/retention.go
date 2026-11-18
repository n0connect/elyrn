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

// Retention deletes in bounded batches: every statement touches at most one batch of rows, in its
// own short transaction, so a large backlog (a day of messages expiring at once, a long pause, a
// conversation burned with years of history) is worked off over a few cycles instead of rolling
// back whole at the statement timeout. A failed batch undoes nothing an earlier batch did, and
// what a cycle leaves is taken up by the next one, oldest first.
const (
	// retentionBatchRows: message rows (or orphan message rows) one statement deletes or caps
	retentionBatchRows = 1000
	// filePartBatchRows: file parts one statement deletes or caps (each part is 256 KiB, so a
	// batch is 16 MiB of bytea)
	filePartBatchRows = 64
	// retentionBatchesPerStep: batches one step runs per cycle; the rest wait for the next cycle
	// (up to 200,000 messages per step and cycle, every five minutes)
	retentionBatchesPerStep = 200
	// orphansPerCycle: orphaned conversations one cycle works on, oldest first
	orphansPerCycle = 100
)

// Batch statements. Each selects one batch by its primary key, oldest first, and acts on exactly
// those rows; the ? are the cutoff (or the new day) and the batch size.
const (
	sqlMessagesExpired = "DELETE FROM messages WHERE (conversation_id, seq) IN " +
		"(SELECT conversation_id, seq FROM messages WHERE " + whereMessageExpired + " ORDER BY expires_on LIMIT ?)"
	sqlMessagesCap = "UPDATE messages SET expires_on = ? WHERE (conversation_id, seq) IN " +
		"(SELECT conversation_id, seq FROM messages WHERE expires_on > ? LIMIT ?)"
	sqlPartsExpired = "DELETE FROM file_parts WHERE (conversation_id, file_id, part) IN " +
		"(SELECT conversation_id, file_id, part FROM file_parts WHERE " + whereMessageExpired + " ORDER BY expires_on LIMIT ?)"
	sqlPartsCap = "UPDATE file_parts SET " + colExpiresOn + " = ? WHERE (conversation_id, file_id, part) IN " +
		"(SELECT conversation_id, file_id, part FROM file_parts WHERE expires_on > ? LIMIT ?)"
	sqlOrphanMessages = "DELETE FROM messages WHERE conversation_id = ? AND seq IN " +
		"(SELECT seq FROM messages WHERE conversation_id = ? ORDER BY seq LIMIT ?)"
	sqlOrphanParts = "DELETE FROM file_parts WHERE conversation_id = ? AND (file_id, part) IN " +
		"(SELECT file_id, part FROM file_parts WHERE conversation_id = ? ORDER BY expires_on, file_id, part LIMIT ?)"
	sqlTombstonesExpired = "DELETE FROM burned_rooms WHERE id IN " +
		"(SELECT id FROM burned_rooms WHERE expires_at <= ? ORDER BY expires_at LIMIT ?)"
)

// PurgeExpired deletes ciphertext (messages and file parts) past its deletion day, invites and
// notes past expiry, expired rooms (oldest first), the rows of deleted conversations (orphans,
// oldest first) and tombstones of burned rooms whose expiry passed. Nothing is kept past latest
// either: a lowered MESSAGE_TTL_DAYS also shortens what is already stored. Every step runs on its
// own, so one that fails (and is logged) does not starve the others; their errors come back
// joined.
func (r *chatRepository) PurgeExpired(today, latest, now time.Time) (PurgeCounts, error) {
	var counts PurgeCounts
	_, capErr := r.inBatches("cap", retentionBatchRows, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlMessagesCap, latest, latest, retentionBatchRows)
	})
	_, partsCapErr := r.inBatches("file parts cap", filePartBatchRows, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlPartsCap, latest, latest, filePartBatchRows)
	})
	var messagesErr, partsErr, invitesErr, notesErr, tombstonesErr error
	counts.Messages, messagesErr = r.inBatches("messages", retentionBatchRows, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlMessagesExpired, today, retentionBatchRows)
	})
	counts.FileParts, partsErr = r.inBatches("file parts", filePartBatchRows, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlPartsExpired, today, filePartBatchRows)
	})
	counts.Invites, invitesErr = r.bulk("invites", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereExpired, now).Delete(&models.Invite{})
	})
	counts.Notes, notesErr = r.bulk("notes", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereExpired, now).Delete(&models.RoomNote{})
	})
	var roomsErr, orphansErr error
	counts.Rooms, roomsErr = r.purgeRooms(now)
	orphanMessages, orphanParts, orphansErr := r.purgeOrphans()
	counts.Messages += orphanMessages
	counts.FileParts += orphanParts
	_, tombstonesErr = r.inBatches("tombstones", retentionBatchRows, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlTombstonesExpired, now, retentionBatchRows)
	})
	return counts, errors.Join(capErr, partsCapErr, messagesErr, partsErr, invitesErr, notesErr, roomsErr, orphansErr, tombstonesErr)
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

// inBatches runs a batch statement (each acting on at most batch rows) until one acts on fewer,
// one fails, or retentionBatchesPerStep ran; every batch commits on its own. Returns the rows
// acted on.
func (r *chatRepository) inBatches(step string, batch int, statement func(tx *gorm.DB) *gorm.DB) (int64, error) {
	rounds := retentionBatchesPerStep
	total, _, err := r.batchesWithin(step, batch, &rounds, statement)
	return total, err
}

// batchesWithin is inBatches drawing its batches from *rounds (a budget shared by several calls).
// done reports that the last batch came back short of batch rows: nothing of this kind is left.
func (r *chatRepository) batchesWithin(step string, batch int, rounds *int, statement func(tx *gorm.DB) *gorm.DB) (int64, bool, error) {
	var total int64
	for *rounds > 0 {
		*rounds--
		affected, err := r.bulk(step, statement)
		total += affected
		if err != nil || affected < int64(batch) {
			return total, err == nil, err
		}
	}
	return total, false, nil
}

// purgeRooms ends up to roomPurgeBatch expired rooms, oldest first, each on its own: one that
// fails is retried next pass and does not keep the others. Their rows become orphans.
func (r *chatRepository) purgeRooms(now time.Time) (int64, error) {
	var expired []uuid.UUID
	if err := r.db().Model(&models.Room{}).Where(whereExpired, now).Order(colExpiresAt).Limit(roomPurgeBatch).Pluck(colID, &expired).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (rooms)", err)
		return 0, err
	}
	var purged int64
	var errs []error
	for _, id := range expired {
		if err := r.DeleteConversation(id, now); err != nil && !errors.Is(err, ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		purged++
	}
	return purged, errors.Join(errs...)
}

// orphanBudget is what one cycle may spend on orphans: a step's batches of each kind, shared by
// every orphan the cycle works on.
type orphanBudget struct {
	messageRounds, partRounds int
}

// purgeOrphans deletes the messages and file parts of deleted conversations in batches, the
// conversation deleted first going first, and drops an orphan once nothing of it is left. No row
// is added to an orphan (its conversation row is gone, so every send and upload finds nothing),
// so a batch smaller than its bound means that kind is done. One orphan that fails is logged and
// retried next cycle; the others go on. Returns the messages and parts removed.
func (r *chatRepository) purgeOrphans() (int64, int64, error) {
	var orphans []uuid.UUID
	if err := r.db().Model(&models.OrphanedConversation{}).Order(colOrphanedOn).Order(colID).
		Limit(orphansPerCycle).Pluck(colID, &orphans).Error; err != nil {
		chatRepoLogger.LogError("ChatRepository.PurgeExpired (orphans)", err)
		return 0, 0, err
	}
	budget := orphanBudget{messageRounds: retentionBatchesPerStep, partRounds: retentionBatchesPerStep}
	var messages, parts int64
	var errs []error
	for _, id := range orphans {
		if budget.messageRounds == 0 || budget.partRounds == 0 {
			break // the rest wait for the next cycle, in the same order
		}
		removedMessages, removedParts, err := r.purgeOrphan(id, &budget)
		messages += removedMessages
		parts += removedParts
		if err != nil {
			errs = append(errs, err)
		}
	}
	return messages, parts, errors.Join(errs...)
}

// purgeOrphan works on one orphan within the cycle's budget, and drops it from the queue once
// both kinds came back short of a batch.
func (r *chatRepository) purgeOrphan(id uuid.UUID, budget *orphanBudget) (int64, int64, error) {
	messages, messagesDone, err := r.batchesWithin("orphan messages", retentionBatchRows, &budget.messageRounds, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlOrphanMessages, id, id, retentionBatchRows)
	})
	if err != nil || !messagesDone {
		return messages, 0, err // more may be left: the orphan stays queued
	}
	parts, partsDone, err := r.batchesWithin("orphan file parts", filePartBatchRows, &budget.partRounds, func(tx *gorm.DB) *gorm.DB {
		return tx.Exec(sqlOrphanParts, id, id, filePartBatchRows)
	})
	if err != nil || !partsDone {
		return messages, parts, err
	}
	_, err = r.bulk("orphan done", func(tx *gorm.DB) *gorm.DB {
		return tx.Where(whereID, id).Delete(&models.OrphanedConversation{})
	})
	return messages, parts, err
}
