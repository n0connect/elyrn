//go:build test

package database

import (
	"time"

	"elyrn/internal/apperr/opcode"
)

// InstanceLockKeyForTesting is the single-instance lock's key, for tests that look the lock up
// in pg_locks. Test builds only.
const InstanceLockKeyForTesting = instanceLockKey

// AcquireInstanceLockForTesting is AcquireInstanceLock with the watcher's pace shortened (check:
// how often it pings; slow: how long a ping may go unanswered before the database is reported
// unreachable), so a test can hold a database outage across many checks. Test builds only.
func AcquireInstanceLockForTesting(lost func(*opcode.Failure), check, slow time.Duration) (*InstanceLock, *opcode.Failure) {
	return acquireInstanceLock(lost, lockTiming{check: check, slow: slow})
}
