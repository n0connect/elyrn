package database

import (
	"errors"
	"strings"
	"testing"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/database"
	"elyrn/internal/encryption"
	"elyrn/tests/testutil"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzValidateStartupConfig$' -fuzztime 60s ./tests/database
// (no database: startup validation reads the environment only)

// validatedVariables is every variable startup validation reads, except PGSSLROOTCERT (a path
// it opens: fuzzing it would read arbitrary files, and its rules are covered by unit tests).
var validatedVariables = []string{
	"APP_ENV", "LOG_LEVEL", "JWT_SECRET", "JWT_SECRET_MIN_LEN", "JWT_ISSUER", "JWT_AUDIENCE", "JWT_EXPIRATION_MINUTES",
	"MASTER_KEY_ACTIVE", "MASTER_KEY_ACTIVE_ID", "MASTER_KEY_OLD", "ACCOUNT_LOOKUP_PEPPER",
	"MAX_REQUEST_BODY_BYTES", "MAX_JSON_DEPTH", "INVITE_TTL_SEC", "MAX_ACTIVE_INVITES", "MAX_CONVERSATIONS_PER_USER",
	"MAX_MESSAGE_BYTES", "MESSAGE_PAGE_LIMIT", "MESSAGE_TTL_DAYS", "ROOM_MAX_MEMBERS", "ROOM_MAX_TTL_HOURS",
	"POW_CHALLENGE_TTL_SEC", "POW_DIFFICULTY", "INTERNAL_ID_LENGTH", "ARGON2_MEMORY_KIB", "ARGON2_TIME",
	"ARGON2_PARALLELISM", "ARGON2_SALT_LENGTH", "ARGON2_HASH_LENGTH", "ARGON2_MAX_CONCURRENT",
	"PENDING_TOKEN_TTL_SEC", "PENDING_CLEANUP_INTERVAL_SEC", "PENDING_ID_BYTES", "RATE_LIMIT_MAX_TOKENS",
	"RATE_LIMIT_REFILL_INTERVAL_SEC", "RATE_LIMIT_CLEANUP_INTERVAL_SEC", "RATE_LIMIT_MAX_BUCKETS", "BACKEND_PORT",
	"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSL_MODE", "ALLOWED_ORIGINS", "TRUSTED_PROXIES",
	"SERVER_READ_HEADER_TIMEOUT_SEC", "SERVER_READ_TIMEOUT_SEC", "SERVER_WRITE_TIMEOUT_SEC", "SERVER_IDLE_TIMEOUT_SEC",
	"SERVER_MAX_HEADER_BYTES", "HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS", "HSTS_PRELOAD",
	"SEC_HEADER_COOP", "SEC_HEADER_CORP", "SEC_HEADER_COEP",
}

// printableASCII reports whether s holds only printable ASCII: every rule and sentence a
// refusal can carry is written that way, so any other byte in a failure line was echoed input.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// FuzzValidateStartupConfig sets one variable (of all the validator reads) to an arbitrary value
// on top of a valid configuration: nothing panics; a refusal is an *opcode.Failure naming a
// variable the validator knows; and the failure line never echoes the value (a line holds only
// printable ASCII, and a value with any other byte never appears in it).
func FuzzValidateStartupConfig(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() {
		encryption.ResetMasterKeysForTesting()
		testutil.TeardownTestEnv(f)
	})
	known := make(map[string]bool, len(validatedVariables))
	for i, variable := range validatedVariables {
		known[variable] = true
		for _, value := range []string{"", "0", "-1", "99999999999999999999", "production", "off", "x\x01y", "\xff\xfe", " 8 ", "1e3"} {
			f.Add(uint8(i), value)
		}
	}
	f.Fuzz(func(t *testing.T, index uint8, value string) {
		if strings.ContainsRune(value, 0) {
			return // the environment cannot hold a NUL byte
		}
		variable := validatedVariables[int(index)%len(validatedVariables)]
		t.Setenv(variable, value)
		encryption.ResetMasterKeysForTesting()
		err := database.ValidateStartupConfig()
		if err == nil {
			return
		}
		var failure *opcode.Failure
		if !errors.As(err, &failure) || !known[failure.Variable] {
			t.Fatalf("%s=%q refused without naming a known variable: %v", variable, value, err)
		}
		line := failure.Error()
		if !printableASCII(line) || (!printableASCII(value) && strings.Contains(line, value)) {
			t.Fatalf("%s=%q: the failure line echoes input: %q", variable, value, line)
		}
	})
}
