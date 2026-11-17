//go:build test
// +build test

package testutil

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"sync"
	"testing"
)

// Secrets are drawn from the CSPRNG once per test binary, exactly as `make setup` does for a
// deployment; no key, secret or pepper is ever written into the repository.
var (
	secretsOnce sync.Once
	jwtSecret   string
	masterKey   string
	pepper      string
)

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// SetupTestEnv sets up test environment variables
func SetupTestEnv(t testing.TB) {
	t.Helper()

	secretsOnce.Do(func() {
		jwtSecret, masterKey, pepper = randomHex(32), randomHex(32), randomHex(32)
	})
	testJWTSecret, testEncryptionKey, testPepper := jwtSecret, masterKey, pepper

	os.Setenv("JWT_SECRET", testJWTSecret)
	os.Setenv("JWT_SECRET_MIN_LEN", "32")
	os.Setenv("JWT_EXPIRATION_MINUTES", "43200")
	os.Setenv("JWT_ISSUER", "noaddx-backend")
	os.Setenv("JWT_AUDIENCE", "noaddx-web")
	os.Setenv("MASTER_KEY_ACTIVE", testEncryptionKey)
	os.Setenv("MASTER_KEY_ACTIVE_ID", "test-key-1")
	os.Setenv("MASTER_KEY_OLD", "")
	os.Setenv("ACCOUNT_LOOKUP_PEPPER", testPepper)
	os.Setenv("MAX_REQUEST_BODY_BYTES", "1048576")
	os.Setenv("MAX_JSON_DEPTH", "2")
	os.Setenv("INVITE_TTL_SEC", "86400")
	os.Setenv("MAX_ACTIVE_INVITES", "5")
	os.Setenv("MAX_CONVERSATIONS_PER_USER", "256")
	os.Setenv("MAX_MESSAGE_BYTES", "8192")
	os.Setenv("MESSAGE_PAGE_LIMIT", "200")
	os.Setenv("MESSAGE_TTL_DAYS", "7")
	os.Setenv("POW_DIFFICULTY", "18") // Minimum allowed; keeps registration helpers fast
	os.Setenv("PENDING_TOKEN_TTL_SEC", "300")
	os.Setenv("PENDING_CLEANUP_INTERVAL_SEC", "60")
	os.Setenv("PENDING_ID_BYTES", "16")
	os.Setenv("INTERNAL_ID_LENGTH", "24")
	os.Setenv("RATE_LIMIT_MAX_TOKENS", "20")
	os.Setenv("RATE_LIMIT_REFILL_INTERVAL_SEC", "3")
	os.Setenv("RATE_LIMIT_CLEANUP_INTERVAL_SEC", "300")
	os.Setenv("RATE_LIMIT_MAX_BUCKETS", "10000")
	os.Setenv("SERVER_READ_HEADER_TIMEOUT_SEC", "5")
	os.Setenv("SERVER_READ_TIMEOUT_SEC", "15")
	os.Setenv("SERVER_WRITE_TIMEOUT_SEC", "15")
	os.Setenv("SERVER_IDLE_TIMEOUT_SEC", "60")
	os.Setenv("SERVER_MAX_HEADER_BYTES", "8192")
	os.Setenv("BACKEND_PORT", "8080")
	os.Setenv("ALLOWED_ORIGINS", "http://localhost:3000")
	setDatabaseDefaults("localhost")
	os.Setenv("APP_ENV", "test")
	os.Setenv("LOG_LEVEL", "error") // Reduce log noise in tests
}

// TeardownTestEnv cleans up test environment variables
func TeardownTestEnv(t testing.TB) {
	t.Helper()

	os.Unsetenv("JWT_SECRET")
	os.Unsetenv("JWT_SECRET_MIN_LEN")
	os.Unsetenv("JWT_EXPIRATION_MINUTES")
	os.Unsetenv("JWT_ISSUER")
	os.Unsetenv("JWT_AUDIENCE")
	os.Unsetenv("MASTER_KEY_ACTIVE")
	os.Unsetenv("MASTER_KEY_ACTIVE_ID")
	os.Unsetenv("MASTER_KEY_OLD")
	os.Unsetenv("ACCOUNT_LOOKUP_PEPPER")
	os.Unsetenv("MAX_REQUEST_BODY_BYTES")
	os.Unsetenv("MAX_JSON_DEPTH")
	os.Unsetenv("INVITE_TTL_SEC")
	os.Unsetenv("MAX_ACTIVE_INVITES")
	os.Unsetenv("MAX_CONVERSATIONS_PER_USER")
	os.Unsetenv("MAX_MESSAGE_BYTES")
	os.Unsetenv("MESSAGE_PAGE_LIMIT")
	os.Unsetenv("MESSAGE_TTL_DAYS")
	os.Unsetenv("POW_DIFFICULTY")
	os.Unsetenv("PENDING_TOKEN_TTL_SEC")
	os.Unsetenv("PENDING_CLEANUP_INTERVAL_SEC")
	os.Unsetenv("PENDING_ID_BYTES")
	os.Unsetenv("INTERNAL_ID_LENGTH")
	os.Unsetenv("RATE_LIMIT_MAX_TOKENS")
	os.Unsetenv("RATE_LIMIT_REFILL_INTERVAL_SEC")
	os.Unsetenv("RATE_LIMIT_CLEANUP_INTERVAL_SEC")
	os.Unsetenv("RATE_LIMIT_MAX_BUCKETS")
	os.Unsetenv("SERVER_READ_HEADER_TIMEOUT_SEC")
	os.Unsetenv("SERVER_READ_TIMEOUT_SEC")
	os.Unsetenv("SERVER_WRITE_TIMEOUT_SEC")
	os.Unsetenv("SERVER_IDLE_TIMEOUT_SEC")
	os.Unsetenv("SERVER_MAX_HEADER_BYTES")
	os.Unsetenv("BACKEND_PORT")
	os.Unsetenv("ALLOWED_ORIGINS")
	os.Unsetenv("APP_ENV")
	os.Unsetenv("LOG_LEVEL")
}
