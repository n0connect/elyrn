//go:build test

package database

import (
	"elyrn/internal/apperr/opcode"
	"elyrn/internal/encryption"
)

// Start connects (bounded wait), loads the master keys and migrates, and returns the failure
// instead of exiting: tests and drills call it (tests/testutil StartDatabase) and fail the test.
// cmd/server runs the steps itself so the single-instance lock is held before the schema is
// touched, and it alone exits (utils.ExitStartup).
func Start() *opcode.Failure {
	if f := Connect(); f != nil {
		return f
	}
	if err := encryption.InitMasterKeys(); err != nil {
		return opcode.As(err, opcode.ConfigInvalid)
	}
	return Migrate(DB)
}
