package utils

import (
	"context"
	"os"
	"runtime/debug"
	"strings"
	"sync"
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
	supervised.Add(1)
	go func() {
		defer supervised.Done()
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
			// The value's type only, never its text (it can wrap a statement's values)
			panicLogger.Error("Goroutine panic recovered: name=%s type=%T stack=%s", name, r, StackFrames(debug.Stack()))
			panicked = true
		}
	}()
	fn(ctx)
	return false
}

// supervised counts the running supervised jobs, so shutdown can wait for them (WaitJobs)
var supervised sync.WaitGroup

// WaitJobs waits for every supervised job to return (their context must already be cancelled),
// at most deadline; it reports whether they all did.
func WaitJobs(deadline time.Duration) bool {
	done := make(chan struct{})
	go func() {
		supervised.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(deadline):
		return false
	}
}

const (
	// stackFrameIndent opens a stack line that names a frame's source file and line
	stackFrameIndent = "\t"
	// stackPCOffset opens the program-counter offset after a frame's source line
	stackPCOffset = " +0x"
)

// StackFrames is a stack trace (debug.Stack) reduced to function names and source lines, the one
// form a recovered panic's stack is logged in (middleware.Recover, supervised jobs). A frame's
// function line ends with its argument list: raw words (pointers, lengths, integers the code
// held, ellipses), so it is cut at its last opening parenthesis (arguments never hold one; a
// receiver's "(*T)" comes before it). A source line ends with its pc offset, cut too. The
// goroutine header and "created by" lines carry neither and stay as they are.
func StackFrames(stack []byte) string {
	lines := strings.Split(strings.TrimRight(string(stack), "\n"), "\n")
	for i, line := range lines {
		switch {
		case strings.HasPrefix(line, stackFrameIndent):
			if at := strings.LastIndex(line, stackPCOffset); at >= 0 {
				lines[i] = line[:at]
			}
		case strings.HasSuffix(line, ")"):
			if at := strings.LastIndexByte(line, '('); at > 0 {
				lines[i] = line[:at]
			}
		}
	}
	return strings.Join(lines, "\n")
}
