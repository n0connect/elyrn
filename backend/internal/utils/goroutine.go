package utils

import (
	"context"
	"os"
	"runtime/debug"
	"time"

	"elyrn/internal/apperr/opcode"
)

var panicLogger = NewLogger("PANIC")

const (
	// MaxRestarts bounds how often a supervised goroutine is revived after panics
	MaxRestarts = 5
	// restartBaseDelay doubles per consecutive panic (RULES.md §17.1 exponential backoff)
	restartBaseDelay = time.Second
	// ExitJobAbandoned is the process exit status after a supervised job is abandoned
	// (EX_SOFTWARE): non-zero, so the container's restart policy starts a fresh process
	ExitJobAbandoned = 70
)

// SafeGoSupervised runs a critical job fn in a goroutine under a supervisor (RULES.md §4.4).
// A normal return ends it. A panic is logged with its stack and fn is restarted with
// exponential backoff, at most MaxRestarts times, and never after ctx is cancelled. A job that
// still panics is abandoned and the process exits (E_JOB_ABANDONED, ExitJobAbandoned): a server
// silently running without its retention or key rotation is worse than a restart.
func SafeGoSupervised(ctx context.Context, name string, fn func(ctx context.Context)) {
	go func() {
		for attempt := 0; attempt <= MaxRestarts; attempt++ {
			if !runRecovered(ctx, name, fn) {
				return
			}
			delay := restartBaseDelay << attempt
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
		panicLogger.Error("Goroutine abandoned after repeated panics: name=%s %s", name, opcode.JobAbandoned)
		os.Exit(ExitJobAbandoned)
	}()
}

// runRecovered reports whether fn panicked.
func runRecovered(ctx context.Context, name string, fn func(ctx context.Context)) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicLogger.Error("Goroutine panic recovered: name=%s panic=%v stack=%s", name, r, string(debug.Stack()))
			panicked = true
		}
	}()
	fn(ctx)
	return false
}
