package utils

import (
	"sync/atomic"
	"time"
)

// The one clock-jump detector. Work that deletes or forgets by the wall clock (retention,
// spent proofs of work) compares the wall clock with the monotonic clock between two of its own
// readings: a wall clock that moved more than ClockJumpTolerance differently from the time that
// actually passed has jumped. Retention also flags what it found (it alone remembers its last
// pass across restarts), so every such job pauses while the clock is in doubt.
const ClockJumpTolerance = time.Minute

var clockJumpFlagged atomic.Bool

// ClockSteady reports whether the wall clock moved with the monotonic clock between prev and now
// (both from time.Now in this process; a zero prev has nothing to compare and is steady).
func ClockSteady(now, prev time.Time) bool {
	if prev.IsZero() {
		return true
	}
	drift := now.Round(0).Sub(prev.Round(0)) - now.Sub(prev) // wall gap minus monotonic gap
	return drift <= ClockJumpTolerance && drift >= -ClockJumpTolerance
}

// FlagClockJump records whether the last retention cycle found the clock untrustworthy.
func FlagClockJump(jumped bool) { clockJumpFlagged.Store(jumped) }

// ClockJumpFlagged reports whether the last retention cycle found the clock untrustworthy.
func ClockJumpFlagged() bool { return clockJumpFlagged.Load() }
