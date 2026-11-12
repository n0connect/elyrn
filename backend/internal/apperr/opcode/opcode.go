// Package opcode registers the failures no request answers: faults of the server's own
// background work and of its startup that only an operator reads in the log. Each has a stable
// E_... id and the one sentence that tells the operator what happened and what to do. The codes
// requests answer with live in package apperr; this package imports nothing of the project, so
// every package (utils included) can name its codes without an import cycle.
package opcode

import "errors"

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
			"retention is paused and spent proofs of work are kept, so nothing is deleted or forgotten early; " +
			"fix time synchronisation (NTP); both resume by themselves once the clock is steady"}
	// JobAbandoned: a supervised background job kept panicking; the process exits non-zero so
	// the restart policy starts a fresh one instead of running without it.
	JobAbandoned = Code{"E_JOB_ABANDONED",
		"a critical background job kept failing and was abandoned; the server exits so its restart " +
			"policy starts it again; if this repeats, read the panic lines above it"}

	// Startup: the server refuses to start (one exit path, utils.ExitStartup). The variable a
	// line names is the one to correct; its value is never logged.

	// SelfTest: the compiled crypto engine gave a wrong known answer.
	SelfTest = Code{"E_SELFTEST",
		"the compiled crypto engine failed its known-answer self-test; do not run this binary; " +
			"rebuild the image from a release (make build) and start again"}
	// ConfigInvalid: an environment variable is missing, malformed or outside its rule.
	ConfigInvalid = Code{"E_CONFIG_INVALID",
		"an environment variable is missing, malformed or outside its rule; correct the variable " +
			"named in this line in .env (docs/operations/configuration-and-tuning.md) and start again"}
	// DBUnreachable: no connection within the bounded startup wait.
	DBUnreachable = Code{"E_DB_UNREACHABLE",
		"the database did not accept a connection within the startup wait; check that PostgreSQL " +
			"runs (docker compose ps), the DB_* settings and the TLS material (make certs); the " +
			"restart policy tries again"}
	// SecondInstance: another server already holds the single-instance lock on this database.
	SecondInstance = Code{"E_SECOND_INSTANCE",
		"another elyrn server already runs on this database; exactly one may run (proofs of work, " +
			"rate limits and live events live in its memory); stop the other one first"}
	// InstanceLockLost: the connection that held the single-instance lock is gone (the driver
	// reports it closed), so PostgreSQL has released the lock or will.
	InstanceLockLost = Code{"E_INSTANCE_LOCK_LOST",
		"the database connection that held the single-instance lock was lost (the database " +
			"restarted or the network failed); the server stops and its restart policy starts it " +
			"again under a fresh lock"}
	// InstanceLockUnreachable: the lock's connection is still open but the database does not
	// answer on it; the session (and the lock) is alive, so the server keeps running.
	InstanceLockUnreachable = Code{"E_INSTANCE_LOCK_UNREACHABLE",
		"the database stopped answering on the single-instance lock's connection, which is still " +
			"open, so the lock is still held and the server keeps running (requests answer 503 " +
			"until the database answers again, and a line says when it does); if this lasts, check " +
			"that PostgreSQL runs and is not paused, and the network between them"}
	// SchemaNewer: the database was migrated by a newer binary.
	SchemaNewer = Code{"E_SCHEMA_NEWER",
		"this database was migrated by a newer elyrn; an older one could damage it, so it does not " +
			"start; run that version (or a newer one)"}
	// Migrate: the schema migration failed and was rolled back.
	Migrate = Code{"E_MIGRATE",
		"the schema migration failed and was rolled back, nothing changed; read the SQLSTATE in " +
			"this line, fix the database (disk space, permissions) and start again"}
	// KeyCheck: the keys in .env do not open what the database holds.
	KeyCheck = Code{"E_KEY_CHECK",
		"the keys in .env do not open this database (the variable is named in this line); restore " +
			"the .env that belongs to it (docs/operations/disaster-recovery.md); never start with new keys"}
	// Listen: the HTTP listener could not start or stopped.
	Listen = Code{"E_LISTEN",
		"the server could not listen on its port, or the listener failed; another process may hold " +
			"the port; the restart policy tries again"}

	// Running server

	// ShutdownLate: background work outlived the shutdown deadline.
	ShutdownLate = Code{"E_SHUTDOWN_LATE",
		"background work did not stop within the shutdown deadline; keys are zeroized and the " +
			"server exits anyway; if this repeats, read the lines above it"}
	// RewrapIncomplete: records still use an old master key after a re-wrap pass.
	RewrapIncomplete = Code{"E_REWRAP_INCOMPLETE",
		"records still use an old master key (a database error interrupted re-wrapping, or some " +
			"records do not open); re-wrapping retries by itself with backoff; keep that key in " +
			"MASTER_KEY_OLD until this line stops"}
	// PepperUnverified: accounts exist, but nothing stored proves the configured pepper yet.
	PepperUnverified = Code{"E_PEPPER_UNVERIFIED",
		"accounts exist but nothing stored proves ACCOUNT_LOOKUP_PEPPER yet; the server runs and " +
			"pins the pepper at the first login of an existing account; if nobody can log in, the " +
			"pepper is wrong: restore the original from the .env backup"}
)

// All lists every code, for the registry's uniqueness checks.
var All = []Code{ClockJump, JobAbandoned, SelfTest, ConfigInvalid, DBUnreachable, SecondInstance,
	InstanceLockLost, InstanceLockUnreachable, SchemaNewer, Migrate, KeyCheck, Listen, ShutdownLate, RewrapIncomplete,
	PepperUnverified}

// Failure is one coded startup or lifecycle failure: the code, the variable or setting it
// concerns (a NAME, never a value) and an optional value-free detail (a rule, a SQLSTATE). It
// is the only error the startup steps return, so the exit path can log it without ever
// formatting an untrusted error text (a driver error names the database user and host).
type Failure struct {
	Code     Code
	Variable string
	Detail   string
}

// Error is the log line: "<id>: <sentence> [variable NAME] [detail]".
func (f *Failure) Error() string {
	line := f.Code.String()
	if f.Variable != "" {
		line += " [variable " + f.Variable + "]"
	}
	if f.Detail != "" {
		line += " [" + f.Detail + "]"
	}
	return line
}

// Fail builds a failure for code about variable (may be empty) with a value-free detail.
func Fail(code Code, variable, detail string) *Failure {
	return &Failure{Code: code, Variable: variable, Detail: detail}
}

// As returns err's coded failure, or a failure under fallback that carries none of err's text
// (an uncoded error may name a user, a host or a value).
func As(err error, fallback Code) *Failure {
	var f *Failure
	if errors.As(err, &f) {
		return f
	}
	return Fail(fallback, "", "")
}
