//go:build test
// +build test

package testutil

import (
	"testing"

	"elyrn/internal/database"
	"elyrn/internal/models"

	"gorm.io/gorm"
)

// InitializeTestDatabase initializes the global database connection for tests
// It also resets global state (rate limiter, pending store) for test isolation
func InitializeTestDatabase(t *testing.T) {
	t.Helper()
	SetupTestEnv(t)
	StartDatabase(t)
	// Reset global state for test isolation
	resetGlobalStateForTesting(t)
}

// StartDatabase is the one way a test brings the database up: the error-returning startup
// (database.Start: connect within the startup wait, master keys, migration), never the exiting
// one, so a database that cannot be reached fails this test instead of ending the test binary.
// The pool a previous test left is closed first, and this test's pool is closed when the test
// ends (after every later-registered cleanup, so a test's own servers stop before it): one pool
// is open at a time, whatever the number of tests (database.Start opens a new pool per call).
func StartDatabase(t testing.TB) {
	t.Helper()
	database.Close()
	if f := database.Start(); f != nil {
		t.Fatalf("database start: %s", f.Error())
	}
	t.Cleanup(database.Close)
}

// resetGlobalStateForTesting resets all global state that could affect test isolation
// SECURITY: This function calls test-only reset functions that are only available
// when compiled with -tags test. In production builds, these functions don't exist.
func resetGlobalStateForTesting(t *testing.T) {
	t.Helper()

	// Reset rate limiter (prevents rate limit state from affecting tests)
	// SECURITY: ResetRateLimiterForTesting is only available in test builds
	// It will NOT be compiled into production binaries
	resetRateLimiterForTesting()

	// Reset pending store (prevents pending registrations from affecting tests)
	// SECURITY: ResetPendingStoreForTesting is only available in test builds
	// It will NOT be compiled into production binaries
	resetPendingStoreForTesting()
}

// allModels lists every table, children before parents
func allModels() []interface{} {
	return []interface{}{&models.FilePart{}, &models.RoomNote{}, &models.Message{}, &models.ConversationMember{}, &models.Room{}, &models.Conversation{},
		&models.Invite{}, &models.User{}, &models.KeyCheck{}, &models.BurnedRoom{}, &models.OrphanedConversation{}}
}

// CleanupTestData removes all test data created during tests
// This should be called in defer after each test that creates data
func CleanupTestData(t *testing.T) {
	t.Helper()

	if database.DB == nil {
		return
	}

	for _, model := range allModels() {
		if err := database.DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(model).Error; err != nil {
			t.Logf("Failed to cleanup %T: %v", model, err)
		}
	}
}
