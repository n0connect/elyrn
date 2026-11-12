package utils

import (
	"log"
	"os"

	"elyrn/internal/apperr/opcode"
)

// ExitStartupFailed is the process exit status of a refused start or a coded stop (EX_CONFIG):
// non-zero, so the container's restart policy and the operator both see it.
const ExitStartupFailed = 78

var startupLogger = NewLogger("STARTUP")

// LogFailure writes a coded failure as one ERROR line: its id, its sentence, the variable's
// NAME and a value-free detail, never a value or a driver's error text. These lines are rare
// and each one matters, so they bypass the flood bound.
func LogFailure(f *opcode.Failure) {
	log.Println(startupLogger.formatMessage(LogLevelERROR, "%s", f.Error()))
}

// ExitStartup is the one exit path of every fatal startup or lifecycle failure: it logs the
// coded failure and exits with ExitStartupFailed. Deferred functions do not run; callers that
// hold key material close it first (cmd/server).
func ExitStartup(f *opcode.Failure) {
	LogFailure(f)
	os.Exit(ExitStartupFailed)
}
