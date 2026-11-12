// Package opcode registers the failures no request answers: faults of the server's own
// background work that only an operator reads in the log. Each has a stable E_... id and the
// one sentence that tells the operator what happened and what to do. The codes requests answer
// with live in package apperr; this package imports nothing, so every package (utils included)
// can name its codes without an import cycle.
package opcode

// Code is one operator-facing failure.
type Code struct {
	ID       string
	Sentence string
}

// String is how a code appears in a log line: "<id>: <sentence>".
func (c Code) String() string {
	return c.ID + ": " + c.Sentence
}

var (
	// ClockJump: the wall clock disagrees with the time that actually passed, or with the last
	// retention pass; deleting by it could destroy messages early, so retention waits.
	ClockJump = Code{"E_CLOCK_JUMP",
		"the system clock moved (it jumped, or is behind the last retention pass, or far ahead of it); " +
			"retention is paused so nothing is deleted early; fix time synchronisation (NTP); " +
			"retention resumes by itself once the clock is steady"}
	// JobAbandoned: a supervised background job kept panicking; the process exits non-zero so
	// the restart policy starts a fresh one instead of running without it.
	JobAbandoned = Code{"E_JOB_ABANDONED",
		"a critical background job kept failing and was abandoned; the server exits so its restart " +
			"policy starts it again; if this repeats, read the panic lines above it"}
)

// All lists every code, for the registry's uniqueness checks.
var All = []Code{ClockJump, JobAbandoned}
