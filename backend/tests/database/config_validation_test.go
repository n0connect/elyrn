package database

import (
	"bytes"
	"errors"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/config"
	"elyrn/internal/database"
	"elyrn/internal/encryption"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"
)

func validate(t *testing.T) error {
	t.Helper()
	encryption.ResetMasterKeysForTesting()
	t.Cleanup(encryption.ResetMasterKeysForTesting)
	return database.ValidateStartupConfig()
}

// Every numeric knob has a minimum and a maximum (RULES.md §5.1): a value outside the range
// stops startup instead of being silently clamped, truncated or overflowed.
func TestValidateStartupConfig_RejectsOutOfRangeValues(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	if err := validate(t); err != nil {
		t.Fatalf("baseline test configuration rejected: %v", err)
	}

	cases := map[string][2]string{
		"argon2 lanes overflow uint8":   {"ARGON2_PARALLELISM", "256"},
		"argon2 memory over 1 GiB":      {"ARGON2_MEMORY_KIB", "2097152"},
		"argon2 memory below floor":     {"ARGON2_MEMORY_KIB", "64"},
		"argon2 time over bound":        {"ARGON2_TIME", "1000"},
		"argon2 salt too short":         {"ARGON2_SALT_LENGTH", "8"},
		"argon2 hash too short":         {"ARGON2_HASH_LENGTH", "8"},
		"jwt min length below 32":       {"JWT_SECRET_MIN_LEN", "8"},
		"jwt secret below 32 bytes":     {"JWT_SECRET", testutil.NewAuthKey(t)[:16]},
		"internal id beyond column":     {"INTERNAL_ID_LENGTH", "40"},
		"internal id too short":         {"INTERNAL_ID_LENGTH", "8"},
		"pending id below 128 bits":     {"PENDING_ID_BYTES", "4"},
		"pow difficulty out of range":   {"POW_DIFFICULTY", "40"},
		"pow difficulty below floor":    {"POW_DIFFICULTY", "4"},
		"unknown sslmode":               {"DB_SSL_MODE", "sometimes"},
		"rate limit buckets unbounded":  {"RATE_LIMIT_MAX_BUCKETS", "100000000"},
		"body limit over 16 MiB":        {"MAX_REQUEST_BODY_BYTES", "99999999"},
		"json depth too deep":           {"MAX_JSON_DEPTH", "64"},
		"invite ttl over 7 days":        {"INVITE_TTL_SEC", "9999999"},
		"session lifetime over a day":   {"JWT_EXPIRATION_MINUTES", "100000"},
		"conversations per user absurd": {"MAX_CONVERSATIONS_PER_USER", "1000000"},
		"non-numeric value":             {"MAX_ACTIVE_INVITES", "five"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(c[0], c[1])
			if err := validate(t); err == nil {
				t.Errorf("%s=%s accepted", c[0], c[1])
			}
		})
	}
}

// Production mode raises the floors: verified TLS to the database and OWASP Argon2 memory.
func TestValidateStartupConfig_ProductionFloors(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_SSL_MODE", "verify-full")
	t.Setenv("ARGON2_MEMORY_KIB", "65536")
	t.Setenv("ARGON2_TIME", "3")
	t.Setenv("DB_PASSWORD", testutil.NewAuthKey(t))
	if err := validate(t); err != nil {
		t.Fatalf("hardened production configuration rejected: %v", err)
	}

	for name, c := range map[string][2]string{
		"plaintext database link":    {"DB_SSL_MODE", "disable"},
		"unauthenticated tls":        {"DB_SSL_MODE", "require"},
		"argon2 below owasp minimum": {"ARGON2_MEMORY_KIB", "16384"},
		"default database password":  {"DB_PASSWORD", "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(c[0], c[1])
			if err := validate(t); err == nil {
				t.Errorf("production accepted %s=%s", c[0], c[1])
			}
		})
	}
}

// Credentials can contain any character without changing the connection parameters
// (a password like "x sslmode=disable" must stay a password).
func TestConnectionURL_EscapesCredentials(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	password := testutil.NewAuthKey(t) + " sslmode=disable host=evil.example '\\"
	user := "app user@x"
	t.Setenv("DB_PASSWORD", password)
	t.Setenv("DB_USER", user)
	t.Setenv("DB_SSL_MODE", "verify-full")

	parsed, err := url.Parse(database.ConnectionURL())
	if err != nil {
		t.Fatalf("connection URL does not parse: %v", err)
	}
	gotPassword, _ := parsed.User.Password()
	if parsed.User.Username() != user || gotPassword != password {
		t.Fatalf("credentials changed in transit: user=%q", parsed.User.Username())
	}
	query := parsed.Query()
	if parsed.Hostname() != config.GetDBHost() || query.Get("sslmode") != "verify-full" || len(query["sslmode"]) != 1 || query.Get("host") != "" {
		t.Fatalf("connection parameters were altered: %s", parsed.Redacted())
	}
}

// captureLog sends the standard logger (every utils.Logger line) to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

// TestStartupRefusal_CodedNamedAndValueFree: every variable the server reads refuses a malformed
// value at start with E_CONFIG_INVALID naming that variable, and neither the refusal nor anything
// logged on the way (the exit path's line included) carries the value. Each value is unique,
// so finding it anywhere would be a leak.
func TestStartupRefusal_CodedNamedAndValueFree(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	if err := validate(t); err != nil {
		t.Fatalf("baseline test configuration rejected: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "not-a-cert.pem")
	if err := os.WriteFile(certFile, []byte("leak-pgsslrootcert-content"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		variable, value string
		production      bool
	}{
		{"APP_ENV", "leak-app-env", false},
		{"LOG_LEVEL", "leak-log-level", false},
		{"JWT_SECRET_MIN_LEN", "leak-min-len", false},
		{"JWT_SECRET", "leak-short", false},
		{"JWT_EXPIRATION_MINUTES", "leak-minutes", false},
		{"MASTER_KEY_ACTIVE", "leak-master-key", false},
		{"MASTER_KEY_ACTIVE_ID", "leak id with spaces", false},
		{"MASTER_KEY_OLD", "leak-old-key-without-colon", false},
		{"ACCOUNT_LOOKUP_PEPPER", "leak-pepper", false},
		{"MAX_REQUEST_BODY_BYTES", "leak-body", false},
		{"MAX_JSON_DEPTH", "leak-depth", false},
		{"INVITE_TTL_SEC", "leak-invite-ttl", false},
		{"MAX_ACTIVE_INVITES", "leak-invites", false},
		{"MAX_CONVERSATIONS_PER_USER", "leak-conversations", false},
		{"MAX_MESSAGE_BYTES", "leak-message-bytes", false},
		{"MESSAGE_PAGE_LIMIT", "leak-page-limit", false},
		{"MESSAGE_TTL_DAYS", "leak-ttl-days", false},
		{"ROOM_MAX_MEMBERS", "leak-room-members", false},
		{"ROOM_MAX_TTL_HOURS", "leak-room-ttl", false},
		{"POW_CHALLENGE_TTL_SEC", "leak-pow-ttl", false},
		{"POW_DIFFICULTY", "leak-pow-difficulty", false},
		{"INTERNAL_ID_LENGTH", "leak-id-length", false},
		{"ARGON2_MEMORY_KIB", "leak-argon2-memory", false},
		{"ARGON2_TIME", "leak-argon2-time", false},
		{"ARGON2_PARALLELISM", "leak-argon2-lanes", false},
		{"ARGON2_SALT_LENGTH", "leak-argon2-salt", false},
		{"ARGON2_HASH_LENGTH", "leak-argon2-hash", false},
		{"ARGON2_MAX_CONCURRENT", "leak-argon2-slots", false},
		{"PENDING_TOKEN_TTL_SEC", "leak-pending-ttl", false},
		{"PENDING_CLEANUP_INTERVAL_SEC", "leak-pending-cleanup", false},
		{"PENDING_ID_BYTES", "leak-pending-id", false},
		{"RATE_LIMIT_MAX_TOKENS", "leak-tokens", false},
		{"RATE_LIMIT_REFILL_INTERVAL_SEC", "leak-refill", false},
		{"RATE_LIMIT_CLEANUP_INTERVAL_SEC", "leak-cleanup", false},
		{"RATE_LIMIT_MAX_BUCKETS", "leak-buckets", false},
		{"BACKEND_PORT", "leak-backend-port", false},
		{"DB_PORT", "leak-db-port", false},
		{"DB_SSL_MODE", "leak-sslmode", false},
		{"PGSSLROOTCERT", certFile, false},
		{"ALLOWED_ORIGINS", "http://leak-origin.example/path", false},
		{"TRUSTED_PROXIES", "leak-proxy", false},
		{"SERVER_READ_HEADER_TIMEOUT_SEC", "leak-read-header", false},
		{"SERVER_READ_TIMEOUT_SEC", "leak-read", false},
		{"SERVER_WRITE_TIMEOUT_SEC", "leak-write", false},
		{"SERVER_IDLE_TIMEOUT_SEC", "leak-idle", false},
		{"SERVER_MAX_HEADER_BYTES", "leak-header-bytes", false},
		{"HSTS_MAX_AGE", "leak-hsts-age", false},
		{"HSTS_INCLUDE_SUBDOMAINS", "leak-hsts-sub", false},
		{"HSTS_PRELOAD", "leak-hsts-preload", false},
		{"SEC_HEADER_COOP", "leak-coop", false},
		{"SEC_HEADER_CORP", "leak-corp", false},
		{"SEC_HEADER_COEP", "leak-coep", false},
		{"SEC_HEADER_COOP", "off", true},
		{"DB_PASSWORD", "leak-pw", true},
	}
	for _, c := range cases {
		t.Run(c.variable+"="+c.value, func(t *testing.T) {
			if c.production {
				t.Setenv("APP_ENV", "production")
				t.Setenv("DB_SSL_MODE", "verify-full")
				t.Setenv("ARGON2_MEMORY_KIB", "65536")
				t.Setenv("DB_PASSWORD", testutil.NewAuthKey(t))
			}
			t.Setenv(c.variable, c.value)
			logged := captureLog(t)
			err := validate(t)
			var f *opcode.Failure
			if !errors.As(err, &f) {
				t.Fatalf("%s=%q: refusal %v is not a coded failure", c.variable, c.value, err)
			}
			if f.Code.ID != opcode.ConfigInvalid.ID || f.Variable != c.variable {
				t.Fatalf("got %s for %s, want %s for %s", f.Code.ID, f.Variable, opcode.ConfigInvalid.ID, c.variable)
			}
			utils.LogFailure(f)
			line := logged.String()
			if !strings.Contains(line, opcode.ConfigInvalid.ID) || !strings.Contains(line, "[variable "+c.variable+"]") {
				t.Fatalf("the exit line does not name the code and the variable: %q", line)
			}
			if c.value != "off" && strings.Contains(line+err.Error(), c.value) {
				t.Fatalf("the value of %s reached the output", c.variable)
			}
			if strings.Contains(line, "leak-pgsslrootcert-content") {
				t.Fatal("the content of PGSSLROOTCERT reached the output")
			}
		})
	}
}

// A malformed entry in a list is reported by its position, never echoed.
func TestStartupRefusal_ListEntriesByPosition(t *testing.T) {
	_, _, err := utils.ParseProxyList("172.29.73.10, leak-entry ,10.0.0.0/8")
	if err == nil || !strings.Contains(err.Error(), "entry 2") || strings.Contains(err.Error(), "leak-entry") {
		t.Fatalf("ParseProxyList: %v", err)
	}
	for _, good := range []string{"http://localhost", "http://localhost,http://127.0.0.1", "https://example.org:8443", "http://abcdefghijklmnop.onion"} {
		if _, err := utils.ParseOrigins(good); err != nil {
			t.Errorf("ParseOrigins(%q): %v", good, err)
		}
	}
	for _, bad := range []string{"", "*", "http://localhost/", "localhost", "ftp://x.example", "http://user@x.example", "http://x.example?q", "http://*.example", "HTTP://X.EXAMPLE"} {
		if _, err := utils.ParseOrigins(bad); err == nil {
			t.Errorf("ParseOrigins(%q) accepted", bad)
		}
	}
}

// Every LogError line reduces its error through the one reducer the database package installs
// (database.LogSafe): a repository or service that logs a driver failure logs its class, never
// the driver's text, which names the database's user, name and host.
func TestLogError_ReducesDriverErrorsToTheirClass(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	broken, err := database.Open("postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pool, err := broken.DB()
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	pingErr := pool.Ping()
	if pingErr == nil {
		t.Fatal("a closed port answered")
	}
	if !strings.Contains(pingErr.Error(), "nobody") {
		t.Fatalf("the driver's own text no longer names the user (%q): this test proves nothing", pingErr.Error())
	}
	buf := captureLog(t)
	for _, wrapped := range []error{pingErr, errors.Join(errors.New("FindByUUID"), pingErr)} {
		utils.NewLogger("USER_REPOSITORY").LogError("TestLogError_ReducesDriverErrorsToTheirClass", wrapped)
	}
	logged := buf.String()
	for _, text := range []string{"nobody", "database=none", "127.0.0.1:1", "failed to connect"} {
		if strings.Contains(logged, text) {
			t.Fatalf("driver text %q reached the log: %s", text, logged)
		}
	}
	if strings.Count(logged, `"error":"database: `) != 2 {
		t.Fatalf("the error was not reduced to its class: %s", logged)
	}
}
