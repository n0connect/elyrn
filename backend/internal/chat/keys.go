package chat

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/encryption"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/store"

	"github.com/google/uuid"
)

// The database is useless without the keys in .env, and the keys are useless without the
// database: VerifyKeys stops them from drifting apart unnoticed, RunRewrap completes a
// master key rotation so the old key can actually be retired.

const (
	pepperCheckName = "pepper"
	// keySampleSize rows per table are tried: one corrupt row must not stop the server,
	// while a wrong key opens none of them
	keySampleSize = 3
	rewrapBatch   = 100
	// maxRewrapBatches bounds the loop (RULES.md §8.1); 100 rows each, it covers any table
	maxRewrapBatches = 1 << 20
)

func sortedIDs(set map[string]struct{}) []string {
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// VerifyKeys refuses keys that cannot open what the database holds. A regenerated .env, or a
// master key dropped from MASTER_KEY_OLD while records still need it, would otherwise start a
// server that answers every account with errors. Every master key id in use must be
// configured and open sample records, and the pepper must be the one the database runs with.
func (s *Service) VerifyKeys() error {
	inUse, err := s.keys.MasterKeyIDsInUse()
	if err != nil {
		return err
	}
	delete(inUse, "") // rows from before key ids existed: no key and no code path opens them
	for _, id := range sortedIDs(inUse) {
		if !encryption.HasMasterKey(id) {
			return opcode.Fail(opcode.KeyCheck, envOldKeys, "records are encrypted under a master key id that is not configured: "+
				"restore that key as MASTER_KEY_ACTIVE or in MASTER_KEY_OLD (the ids in use: SELECT DISTINCT master_key_id FROM users)")
		}
		opens, err := s.opensSample(id)
		if err != nil {
			return err
		}
		if !opens {
			return opcode.Fail(opcode.KeyCheck, envOldKeys, "a configured master key does not open the records stored under its id")
		}
	}
	for _, id := range encryption.OldMasterKeyIDs() {
		if _, used := inUse[id]; !used {
			s.logger.Info("Old master key %s encrypts nothing any more: remove it from MASTER_KEY_OLD", id)
		}
	}
	return s.verifyPepper(inUse)
}

// opensSample reports whether keyID decrypts any of a few records stored under it.
func (s *Service) opensSample(keyID string) (bool, error) {
	users, err := s.keys.UsersUnderKey(keyID, 0, keySampleSize)
	if err != nil {
		return false, err
	}
	members, err := s.keys.MembersUnderKey(keyID, models.ConversationMember{}, keySampleSize)
	if err != nil {
		return false, err
	}
	invites, err := s.keys.InvitesUnderKey(keyID, uuid.Nil, keySampleSize)
	if err != nil {
		return false, err
	}
	for i := range users {
		if _, err := encryption.DecryptUserKey(users[i].EncryptedKey, keyID); err == nil {
			return true, nil
		}
	}
	for i := range members {
		if _, err := memberRefUUID(&members[i]); err == nil {
			return true, nil
		}
	}
	for i := range invites {
		if _, err := openInviteCreator(&invites[i]); err == nil {
			return true, nil
		}
	}
	return len(users)+len(members)+len(invites) == 0, nil
}

// envOldKeys names where a missing or wrong master key belongs (key ids are never logged)
const envOldKeys = "MASTER_KEY_OLD"

var errPepperChanged = opcode.Fail(opcode.KeyCheck, "ACCOUNT_LOOKUP_PEPPER",
	"is not the pepper this database was created with: restore the original (it can never change, every account is keyed by it)")

// The pepper floor. A database whose accounts predate the pepper check, and whose stored
// conversations cannot prove the pepper yet, runs unverified (E_PEPPER_UNVERIFIED). At the first
// such start the highest account id is stored as the floor ("pepper-floor" in key_checks; a
// number, no identifier). An account at or below the floor existed before any unverified run,
// so it was created under the right pepper; under a wrong one nobody can log in to it, so none
// of its conversations can be created with a wrong pepper. Only those conversations prove or
// contradict the pepper: accounts registered meanwhile (possibly under a wrong pepper) never
// get it pinned, nor lock the right one out.
const (
	pepperFloorName = "pepper-floor"
	// maxPepperProofScan bounds how many memberships one start reads looking for a proof
	maxPepperProofScan = 10000
)

// verifyPepper compares the pepper with the commitment pinned at the first run. A database
// that predates the check gets the commitment only once stored pseudonyms prove the pepper,
// so a wrong pepper is never pinned (which would then lock the right one out).
func (s *Service) verifyPepper(inUse map[string]struct{}) error {
	check, err := identity.PepperCheck()
	if err != nil {
		return err
	}
	pinned, ok, err := s.keys.KeyCheck(pepperCheckName)
	if err != nil {
		return err
	}
	if ok {
		if !cryptoengine.ConstantTimeEqual([]byte(pinned), []byte(check)) {
			return errPepperChanged
		}
		return nil
	}
	proven, err := s.pepperProven(inUse)
	if err != nil {
		return err
	}
	if !proven {
		if err := s.markPepperFloor(); err != nil {
			return err
		}
		s.logger.Error("VerifyKeys: %s", opcode.PepperUnverified)
		return nil
	}
	return s.keys.PinKeyCheck(pepperCheckName, check)
}

// markPepperFloor stores the floor once (never moved afterwards).
func (s *Service) markPepperFloor() error {
	maxID, err := s.keys.MaxUserID()
	if err != nil {
		return err
	}
	return s.keys.PinKeyCheck(pepperFloorName, strconv.FormatUint(uint64(maxID), 10))
}

// pepperFloor reads the floor; ok is false before the first unverified start.
func (s *Service) pepperFloor() (floor uint64, ok bool, err error) {
	raw, ok, err := s.keys.KeyCheck(pepperFloorName)
	if err != nil || !ok {
		return 0, false, err
	}
	floor, err = strconv.ParseUint(raw, 10, 64)
	return floor, err == nil, err
}

// pepperProven: an empty database (the first run) takes any pepper; otherwise a membership
// pseudonym recomputed with the pepper must match the stored one. A mismatch is an error. Once
// a floor exists, only memberships of accounts at or below it count.
func (s *Service) pepperProven(inUse map[string]struct{}) (bool, error) {
	hasUsers, err := s.keys.HasUsers()
	if err != nil || !hasUsers {
		return !hasUsers, err
	}
	floor, hasFloor, err := s.pepperFloor()
	if err != nil {
		return false, err
	}
	for _, id := range sortedIDs(inUse) {
		var after models.ConversationMember
		for scanned := 0; scanned < maxPepperProofScan; {
			members, err := s.keys.MembersUnderKey(id, after, rewrapBatch)
			if err != nil {
				return false, err
			}
			if len(members) == 0 {
				break
			}
			for i := range members {
				after, scanned = members[i], scanned+1
				proven, decided, err := s.memberProves(&members[i], floor, hasFloor)
				if err != nil || decided {
					return proven, err
				}
			}
		}
	}
	return false, nil
}

// memberProves recomputes one membership's pseudonym: decided is false for a row that cannot be
// opened or belongs to an account above the floor.
func (s *Service) memberProves(member *models.ConversationMember, floor uint64, hasFloor bool) (proven, decided bool, err error) {
	userUUID, err := memberRefUUID(member)
	if err != nil {
		return false, false, nil
	}
	if hasFloor {
		user, err := s.users.FindByUUID(userUUID)
		if errors.Is(err, store.ErrUnavailable) {
			return false, false, err
		}
		if err != nil || user == nil || uint64(user.ID) > floor {
			return false, false, nil
		}
	}
	tag, err := identity.ConversationTag(userUUID, member.ConversationID)
	if err != nil {
		return false, false, err
	}
	if tag != member.MemberTag {
		return false, true, errPepperChanged
	}
	return true, true, nil
}

// Re-wrapping retries: a pass that a database error interrupted, or that left records it could
// not open, is repeated with exponential backoff (rewrapRetryFirst doubling up to
// rewrapRetryMax) until no record names an old key, logging E_REWRAP_INCOMPLETE after each
// such pass, so the operator never retires a key that still protects something.
const (
	rewrapRetryFirst = time.Minute
	rewrapRetryMax   = time.Hour
	// maxRewrapPasses bounds the loop (RULES.md §8.1); at one an hour it outlives any deployment
	maxRewrapPasses = 1 << 20
)

// RunRewrap moves every record still under an old master key to the active one, a batch at
// a time, so a rotated-out (possibly exposed) key stops protecting anything and can leave
// MASTER_KEY_OLD. Rows written meanwhile already use the active key, and each update applies
// only while the row still names the old key. Rows that do not open keep their old key.
func (s *Service) RunRewrap(ctx context.Context) {
	delay := rewrapRetryFirst
	for pass := 0; pass < maxRewrapPasses && ctx.Err() == nil; pass++ {
		remaining, err := s.rewrapPass(ctx)
		if err == nil && remaining == 0 {
			return
		}
		if err != nil {
			s.logger.LogError("RunRewrap", err)
		}
		s.logger.Error("RunRewrap: %d old master key ids still in use, next pass in %s: %s", remaining, delay, opcode.RewrapIncomplete)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(2*delay, rewrapRetryMax)
	}
}

// rewrapPass re-wraps every old-key record once and reports how many old key ids records still
// name afterwards.
func (s *Service) rewrapPass(ctx context.Context) (remaining int, err error) {
	active := encryption.ActiveMasterKeyID()
	inUse, err := s.keys.MasterKeyIDsInUse()
	if err != nil {
		return 0, err
	}
	moved, stuck := 0, 0
	for _, id := range oldKeyIDs(inUse, active) {
		m, st, err := s.rewrapKey(ctx, id, active)
		moved, stuck = moved+m, stuck+st
		if err != nil {
			return len(oldKeyIDs(inUse, active)), err
		}
	}
	switch {
	case stuck > 0:
		s.logger.Warn("Master key rotation: %d records re-wrapped, %d do not open and keep their old key", moved, stuck)
	case moved > 0:
		s.logger.Info("Master key rotation: %d records re-wrapped", moved)
	}
	if inUse, err = s.keys.MasterKeyIDsInUse(); err != nil {
		return 0, err
	}
	remaining = len(oldKeyIDs(inUse, active))
	if remaining == 0 && moved > 0 {
		s.logger.Info("Master key rotation complete: no record uses an old key any more, MASTER_KEY_OLD can be emptied")
	}
	return remaining, nil
}

// oldKeyIDs lists the ids in use other than the active one; "" (rows from before key ids
// existed) is no key at all and is never re-wrapped.
func oldKeyIDs(inUse map[string]struct{}, active string) []string {
	ids := make([]string, 0, len(inUse))
	for _, id := range sortedIDs(inUse) {
		if id != active && id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// rewrapKey walks the three tables in primary-key order; the cursors move past every row,
// re-wrapped or not, so a row that cannot be opened is visited once per pass.
func (s *Service) rewrapKey(ctx context.Context, from, to string) (moved, stuck int, err error) {
	count := func(err error) {
		if err == nil {
			moved++
		} else {
			stuck++
		}
	}
	var (
		afterUser   uint
		afterMember models.ConversationMember
		afterInvite uuid.UUID
	)
	for batch := 0; batch < maxRewrapBatches && ctx.Err() == nil; batch++ {
		users, errUsers := s.keys.UsersUnderKey(from, afterUser, rewrapBatch)
		members, errMembers := s.keys.MembersUnderKey(from, afterMember, rewrapBatch)
		invites, errInvites := s.keys.InvitesUnderKey(from, afterInvite, rewrapBatch)
		if err := errors.Join(errUsers, errMembers, errInvites); err != nil {
			return moved, stuck, err
		}
		if len(users)+len(members)+len(invites) == 0 {
			return moved, stuck, nil
		}
		for i := range users {
			afterUser = users[i].ID
			count(s.rewrapUser(&users[i], from, to))
		}
		for i := range members {
			afterMember = members[i]
			count(s.rewrapMember(&members[i], from, to))
		}
		for i := range invites {
			afterInvite = invites[i].ID
			count(s.rewrapInvite(&invites[i], from, to))
		}
	}
	return moved, stuck, ctx.Err()
}

func (s *Service) rewrapUser(user *models.User, from, to string) error {
	key, err := encryption.DecryptUserKey(user.EncryptedKey, from)
	if err != nil {
		return err
	}
	enc, err := encryption.EncryptWithMasterKey(hex.EncodeToString(key))
	if err != nil {
		return err
	}
	return s.keys.RewrapUser(user.ID, from, to, enc)
}

// Re-wrapping first verifies the record (tag included): nothing unauthenticated is re-sealed
func (s *Service) rewrapMember(member *models.ConversationMember, from, to string) error {
	userUUID, err := openMemberRef(member)
	if err != nil {
		return err
	}
	enc, err := encryption.SealWithActiveKey(userUUID, memberRefAAD(member.MemberTag, member.ConversationID))
	if err != nil {
		return err
	}
	return s.keys.RewrapMember(member, from, to, enc)
}

func (s *Service) rewrapInvite(invite *models.Invite, from, to string) error {
	creatorUUID, err := openInviteCreator(invite)
	if err != nil {
		return err
	}
	enc, err := encryption.SealWithActiveKey(creatorUUID, inviteCreatorAAD(invite.Lookup, invite.ID))
	if err != nil {
		return err
	}
	return s.keys.RewrapInvite(invite.ID, from, to, enc)
}
