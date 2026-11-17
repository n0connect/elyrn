package chat

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/config"
	"elyrn/internal/utils"
)

// ---------- retention ----------

// Retention deletes by the wall clock, so a clock that jumps would destroy data: forward, it
// expires everything at once; backward, the cap step rewrites expiry dates earlier and messages
// die early once the clock is put right. Each cycle therefore purges only when the clock can be
// trusted (clockTrusted), and remembers when it last purged (the retention mark, in key_checks):
//  1. while running, the wall clock must have moved with the monotonic clock since the previous
//     cycle (utils.ClockSteady, within utils.ClockJumpTolerance); a jump pauses that cycle;
//  2. now must not be before the last purge: a clock behind it went back, and purging (the cap
//     above all) would be wrong until it catches up again;
//  3. at boot there is no previous cycle to compare with, so a time far past the last purge
//     (more than maxRetentionGap) waits one cycle: a boot clock that is wrong (no RTC, NTP not
//     yet synced) usually gets corrected meanwhile, which rule 1 then sees; a gap that is still
//     there after a steady cycle is real downtime, and purging proceeds.
//
// A paused cycle deletes nothing and logs E_CLOCK_JUMP; expired data stays unreadable meanwhile
// (reads filter by expiry themselves).
const (
	// maxRetentionGapTTLs: a boot more than this many maximum retention periods after the last
	// purge waits for a steady cycle (rule 3)
	maxRetentionGapTTLs = 2
)

// maxRetentionGap is rule 3's bound: twice the longest retention MESSAGE_TTL_DAYS allows.
func maxRetentionGap() time.Duration {
	return maxRetentionGapTTLs * time.Duration(config.MaxMessageTTLDays()) * day
}

// clockTrusted applies the rules above. prev is the previous cycle's reading in this process
// (zero at boot), mark the last purge (zero if retention never ran on this database).
func clockTrusted(now, prev, mark time.Time) bool {
	if !utils.ClockSteady(now, prev) {
		return false
	}
	if mark.IsZero() {
		return true
	}
	if now.Before(mark) {
		return false
	}
	return !prev.IsZero() || !now.After(mark.Add(maxRetentionGap()))
}

// PurgeExpired runs one retention pass at now as the first cycle after boot does (no previous
// reading in this process; see retentionCycle).
func (s *Service) PurgeExpired(now time.Time) error {
	return s.retentionCycle(now, time.Time{})
}

// retentionCycle purges what is expired at now, unless the clock cannot be trusted (then it
// deletes nothing and logs E_CLOCK_JUMP): ciphertext past its deletion day, expired invites and
// notes, and expired rooms with everything in them, and keeps no ciphertext past the deletion
// day of a message sent now (MESSAGE_TTL_DAYS may have shrunk). The mark moves to now once
// the pass has run, also when a step failed: the clock was trusted either way. Every cycle, paused
// or not, then counts the stored file parts afresh (RecountFileParts).
func (s *Service) retentionCycle(now, prev time.Time) error {
	return errors.Join(s.purgeCycle(now, prev), s.RecountFileParts())
}

// purgeCycle is retentionCycle's purge, run only on a trusted clock.
func (s *Service) purgeCycle(now, prev time.Time) error {
	mark, _, err := s.keys.RetentionMark()
	if err != nil {
		return err
	}
	trusted := clockTrusted(now, prev, mark)
	utils.FlagClockJump(!trusted)
	if !trusted {
		s.logger.Error("RunRetention: %s", opcode.ClockJump)
		return nil
	}
	counts, purgeErr := s.chats.PurgeExpired(deletionCutoff(now), expiryDay(now), now.UTC())
	s.logger.Debug("PurgeExpired: removed %d messages, %d file parts, %d invites, %d notes, %d rooms",
		counts.Messages, counts.FileParts, counts.Invites, counts.Notes, counts.Rooms)
	return errors.Join(purgeErr, s.keys.SaveRetentionMark(now))
}

const (
	// Rooms expire on the hour and stop answering at once; this bounds how long their rows
	// stay on disk afterwards
	retentionInterval = 5 * time.Minute
	// maxRetentionCycles bounds the loop (RULES.md §8.1); every five minutes it outlives any deployment
	maxRetentionCycles = 1 << 22
)

// Retention liveness, for the healthcheck: each cycle records when it began, on the monotonic
// clock (time since processStart), so a clock jump never makes retention look dead or alive.
var (
	processStart  = time.Now()
	retentionBeat atomic.Int64
)

// retentionSilence: no cycle began for this long means retention is stuck (three missed cycles)
const retentionSilence = 3 * retentionInterval

// RetentionAlive reports whether a retention cycle began within retentionSilence (or the process
// is younger than that).
func RetentionAlive() bool {
	return time.Since(processStart)-time.Duration(retentionBeat.Load()) <= retentionSilence
}

// RunRetention runs a retention cycle now and then every five minutes until ctx ends, each
// compared with the one before it (clockTrusted).
func (s *Service) RunRetention(ctx context.Context) {
	ticker := time.NewTicker(retentionInterval)
	defer ticker.Stop()
	var prev time.Time
	for cycle := 0; cycle < maxRetentionCycles; cycle++ {
		retentionBeat.Store(int64(time.Since(processStart)))
		now := time.Now()
		if err := s.retentionCycle(now, prev); err != nil {
			s.logger.LogError("RunRetention", err)
		}
		prev = now
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
