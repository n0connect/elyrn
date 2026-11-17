package chat

// Files: a file is stored as equal-sized sealed parts and announced by an ordinary message whose
// ciphertext carries its key, so exactly the members who can read that message can open it. The
// server sees per conversation: which member stored how many parts of a file id, and when (to
// the day), and which member fetched which part.

import (
	"encoding/base64"
	"errors"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/models"
	"elyrn/internal/store"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

var (
	// ErrFilePartOutOfOrder: a later part of a file whose live part 0 the caller did not store
	ErrFilePartOutOfOrder = errors.New("file part out of order")
	// ErrFileQuotaReached: the conversation holds FILE_CONVERSATION_QUOTA_BYTES of parts
	ErrFileQuotaReached = errors.New("file quota reached")
	// ErrFileStoreFull: the server holds FILE_STORE_MAX_BYTES of parts, or does not know yet
	ErrFileStoreFull = errors.New("file store full")
)

const (
	// FirstFilePart opens a file: its uploader owns the file id in the conversation
	FirstFilePart = 0
	// unknownGeneration is a mark no recount ever reaches: a deletion under it is not subtracted
	unknownGeneration = ^uint64(0)
)

// partCounter is the in-process count of stored file parts that FILE_STORE_MAX_BYTES is checked
// against before every insert, so the check costs no count(*) per upload. The server is a single
// instance (database.AcquireInstanceLock), so one process sees every insert and delete. It is set
// from the database at start and again by every retention cycle, and adjusted in between:
//   - an upload reserves its part before inserting (refused when stored + reserved would pass the
//     bound) and settles the reservation once its transaction ended, counting it when it committed;
//   - a burn or an account deletion subtracts the parts it removed once it committed, unless a
//     recount ran meanwhile (it may already have seen the delete: subtracting again would count
//     too few).
//
// Every uncertainty resolves towards "full": before the first count it refuses every insert, and
// an insert that commits during a recount may be counted twice until the next one.
type partCounter struct {
	mu         *utils.SafeMutex // a leaf lock: held for arithmetic only, never across a statement
	known      bool
	stored     int64
	reserved   int64
	generation uint64 // bumped by every recount
}

var storedParts = &partCounter{mu: utils.NewSafeMutex()}

// with runs fn under the counter's lock.
func (c *partCounter) with(fn func()) error {
	if err := c.mu.Lock(); err != nil {
		return err
	}
	defer c.mu.Unlock()
	fn()
	return nil
}

// set records a fresh count of the stored parts.
func (c *partCounter) set(n int64) error {
	return c.with(func() {
		c.stored, c.known = n, true
		c.generation++
	})
}

// reserve takes room for one part, or answers ErrFileStoreFull when limit parts are stored or
// reserved already, or the count is not known yet.
func (c *partCounter) reserve(limit int64) error {
	full := false
	if err := c.with(func() {
		full = !c.known || c.stored+c.reserved >= limit
		if !full {
			c.reserved++
		}
	}); err != nil {
		return err
	}
	if full {
		return ErrFileStoreFull
	}
	return nil
}

// settle ends a reservation: the part is counted as stored when its insert committed.
func (c *partCounter) settle(committed bool) error {
	return c.with(func() {
		c.reserved--
		if committed {
			c.stored++
		}
	})
}

// mark is the recount generation a deletion starts in.
func (c *partCounter) mark() (uint64, error) {
	var generation uint64
	err := c.with(func() { generation = c.generation })
	return generation, err
}

// drop subtracts n parts a committed deletion removed, unless a recount ran since mark.
func (c *partCounter) drop(n int64, since uint64) error {
	return c.with(func() {
		if c.generation == since {
			c.stored = max(c.stored-n, 0)
		}
	})
}

// storeLimitParts is how many parts FILE_STORE_MAX_BYTES holds.
func storeLimitParts() int64 {
	return config.GetFileStoreMaxBytes() / utils.FilePartBytes
}

// RecountFileParts sets the stored-parts counter from the database: at start (cmd/server) and in
// every retention cycle. On failure the counter keeps its value (unknown at start: full).
func (s *Service) RecountFileParts() error {
	n, err := s.chats.CountAllFileParts()
	if err != nil {
		return err
	}
	return storedParts.set(n)
}

// partsRemoved accounts for the parts a committed deletion removed (logged, never failing the
// deletion: the next recount corrects the counter either way).
func (s *Service) partsRemoved(n int64, since uint64) {
	if n == 0 {
		return
	}
	if err := storedParts.drop(n, since); err != nil {
		s.logger.LogError("partsRemoved", err)
	}
}

// partsMark is the counter generation a deletion starts in; a failure reads as "a recount ran"
// (the deletion is then not subtracted: the counter errs towards full).
func (s *Service) partsMark() uint64 {
	generation, err := storedParts.mark()
	if err != nil {
		s.logger.LogError("partsMark", err)
		return unknownGeneration
	}
	return generation
}

// UploadFilePart stores one sealed part of a file in a conversation the caller is a member of.
// Part 0 opens the file for its uploader; a later part needs that live part 0 by the same
// uploader, and takes its deletion day so a file expires as one. A part already stored answers
// like a duplicate message: ErrConflict when it is the caller's own identical earlier upload,
// ErrIDTaken otherwise. Runs under the conversation row lock, so a burn, a room's expiry or a
// leave never interleaves with it, and the conversation's quota is counted exactly.
func (s *Service) UploadFilePart(me *Member, conversationID uuid.UUID, rawFileID string, part int, data string) error {
	fileID, okID := utils.ParseCanonicalUUIDv4(rawFileID)
	raw, okData := utils.DecodeExact(data, utils.FilePartSealedBytes)
	if !okID || !okData || part < FirstFilePart || int64(part) >= utils.FilePartCount(config.GetMaxFileBytes()) {
		return ErrInvalidInput
	}
	if _, err := s.liveRoom(s.chats, conversationID); err != nil {
		return err
	}
	reserved := false
	err := s.chats.Transaction(func(tx store.ChatRepository) error {
		if _, err := tx.LockConversation(conversationID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		member, err := s.requireMembership(tx, me, conversationID)
		if err != nil {
			return err
		}
		// A stored part is judged first: a resend after a lost answer answers "stored" even when
		// the quota filled meanwhile (duplicates.go: membership was checked, no existence oracle)
		if err := filePartDuplicate(tx, member.MemberTag, conversationID, fileID, part, raw); err != nil {
			return err
		}
		now := time.Now()
		expiresOn, err := partExpiry(tx, member.MemberTag, conversationID, fileID, part, now)
		if err != nil {
			return err
		}
		if err := checkFileQuota(tx, conversationID); err != nil {
			return err
		}
		if err := storedParts.reserve(storeLimitParts()); err != nil {
			return err
		}
		reserved = true
		err = tx.CreateFilePart(&models.FilePart{ConversationID: conversationID, FileID: fileID, Part: part,
			UploaderTag: member.MemberTag, Data: raw, ExpiresOn: expiresOn})
		if errors.Is(err, store.ErrConflict) {
			return ErrIDTaken // the lock serialises uploads, so a holder found now is never the caller's own
		}
		return err
	})
	if reserved {
		if settleErr := storedParts.settle(err == nil); settleErr != nil {
			s.logger.LogError("UploadFilePart: settle", settleErr)
		}
	}
	if err != nil {
		return err
	}
	s.logger.Debug("UploadFilePart: part stored")
	return nil
}

// filePartDuplicate is nil when no part is stored under (conversation, file, part), otherwise
// ErrConflict (the caller's own byte-identical earlier upload) or ErrIDTaken (anything else).
func filePartDuplicate(tx store.ChatRepository, uploaderTag string, conversationID, fileID uuid.UUID, part int, raw []byte) error {
	existing, err := tx.FindFilePart(conversationID, fileID, part)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return duplicateAnswer(sameSend(existing.UploaderTag == uploaderTag, string(existing.Data), string(raw)))
}

// partExpiry is the deletion day of a new part: the message rule for part 0, part 0's own day for
// a later part, which needs that live part 0 stored by the same uploader.
func partExpiry(tx store.ChatRepository, uploaderTag string, conversationID, fileID uuid.UUID, part int, now time.Time) (time.Time, error) {
	if part == FirstFilePart {
		return expiryDay(now), nil
	}
	opened, err := tx.FindFileStart(conversationID, fileID, deletionCutoff(now))
	if errors.Is(err, store.ErrNotFound) {
		return time.Time{}, ErrFilePartOutOfOrder
	}
	if err != nil {
		return time.Time{}, err
	}
	if opened.UploaderTag != uploaderTag {
		return time.Time{}, ErrFilePartOutOfOrder
	}
	return opened.ExpiresOn, nil
}

// checkFileQuota refuses a part that would take the conversation past its quota.
func checkFileQuota(tx store.ChatRepository, conversationID uuid.UUID) error {
	stored, err := tx.CountFileParts(conversationID)
	if err != nil {
		return err
	}
	if (stored+1)*utils.FilePartBytes > config.GetFileConversationQuotaBytes() {
		return ErrFileQuotaReached
	}
	return nil
}

// ReadFilePart returns one live part, base64url, to a member of the conversation. A missing or
// expired part, an expired room and a non-member all answer ErrNotFound alike.
func (s *Service) ReadFilePart(me *Member, conversationID, fileID uuid.UUID, part int) (string, error) {
	if _, err := s.requireMembership(s.chats, me, conversationID); err != nil {
		return "", err
	}
	if _, err := s.liveRoom(s.chats, conversationID); err != nil {
		return "", err
	}
	stored, err := s.chats.LiveFilePart(conversationID, fileID, part, deletionCutoff(time.Now()))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(stored.Data), nil
}
