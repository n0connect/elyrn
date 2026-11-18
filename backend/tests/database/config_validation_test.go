package database

import (
	"bytes"
	"errors"
	"log"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

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
		"session lifetime over a year":  {"JWT_EXPIRATION_MINUTES", "525601"},
		"conversations per user absurd": {"MAX_CONVERSATIONS_PER_USER", "1000000"},
		"non-numeric value":             {"MAX_ACTIVE_INVITES", "five"},
		"file below one part":           {config.EnvMaxFileBytes, "262143"},
		"file above its bound":          {config.EnvMaxFileBytes, "104857601"},
		"file quota below one part":     {config.EnvFileConversationQuotaBytes, "1"},
		"file store above its bound":    {config.EnvFileStoreMaxBytes, "1099511627777"},
		"file store not a number":       {config.EnvFileStoreMaxBytes, "2GiB"},
		"file budget above its bound":   {config.EnvFileAccountDailyBytes, "10737418241"},
		"proxies: the whole internet":   {config.EnvTrustedProxies, "0.0.0.0/0"},
		"proxies: wider than /8":        {config.EnvTrustedProxies, "172.29.73.10,10.0.0.0/7"},
		"proxies: wider than /16":       {config.EnvTrustedProxies, "2001:db8::/15"},
		"proxies: mapped IPv4 internet": {config.EnvTrustedProxies, "::ffff:0:0/96"},
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

// The session lifetime is accepted from 1 minute to 365 days, defaults to 30 days, and a value
// whose nanoseconds would wrap time.Duration back into the range is refused, not wrapped.
func TestValidateStartupConfig_SessionLifetimeBounds(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	t.Run("default is 30 days", func(t *testing.T) {
		t.Setenv("JWT_EXPIRATION_MINUTES", "")
		if got, want := config.GetJWTExpiration(), 30*24*time.Hour; got != want {
			t.Fatalf("default session lifetime %v, want %v", got, want)
		}
		if err := validate(t); err != nil {
			t.Fatalf("default session lifetime rejected: %v", err)
		}
	})

	for _, minutes := range []int{config.MinJWTExpirationMinutes, 43200, config.MaxJWTExpirationMinutes} {
		value := strconv.Itoa(minutes)
		t.Run("accepts "+value, func(t *testing.T) {
			t.Setenv("JWT_EXPIRATION_MINUTES", value)
			if err := validate(t); err != nil {
				t.Fatalf("JWT_EXPIRATION_MINUTES=%s rejected: %v", value, err)
			}
			if got, want := config.GetJWTExpiration(), time.Duration(minutes)*time.Minute; got != want {
				t.Fatalf("JWT_EXPIRATION_MINUTES=%s read as %v, want %v", value, got, want)
			}
		})
	}

	// 307488935 minutes overflows int64 nanoseconds and would wrap to exactly 43200 minutes
	for _, value := range []string{"0", "-1", strconv.Itoa(config.MaxJWTExpirationMinutes + 1), "307488935", "1e3"} {
		t.Run("refuses "+value, func(t *testing.T) {
			t.Setenv("JWT_EXPIRATION_MINUTES", value)
			if err := validate(t); err == nil {
				t.Fatalf("JWT_EXPIRATION_MINUTES=%q accepted", value)
			}
		})
	}
}

// Every whole-seconds setting is range-checked as an integer before it becomes a duration: its
// maximum is accepted and read exactly, and every count above it is refused, including the
// largest count whose nanoseconds still fit int64, the first that does not, and a count that
// would wrap time.Duration to exactly an accepted value (seconds + 2^55: 2^55 s is 2^64 ns times
// 1953125, so the product wraps to the same nanoseconds).
func TestValidateStartupConfig_SecondsSettingsNeverWrap(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	const wrapPeriodSeconds = int64(1) << 55
	maxUnwrapped := int64(math.MaxInt64 / int64(time.Second))
	settings := []struct {
		key  string
		max  int
		read func() time.Duration
	}{
		{config.EnvInviteTTLSeconds, config.MaxInviteTTLSeconds, config.GetInviteTTL},
		{config.EnvPendingTokenTTLSeconds, config.MaxPendingTokenTTLSeconds, config.GetPendingTokenTTL},
		{config.EnvPendingCleanupIntervalSeconds, config.MaxPendingCleanupSeconds, config.GetPendingCleanupInterval},
		{config.EnvServerReadHeaderTimeoutSeconds, config.MaxServerReadHeaderTimeoutSeconds, config.GetServerReadHeaderTimeout},
		{config.EnvServerReadTimeoutSeconds, config.MaxServerReadTimeoutSeconds, config.GetServerReadTimeout},
		{config.EnvServerWriteTimeoutSeconds, config.MaxServerWriteTimeoutSeconds, config.GetServerWriteTimeout},
		{config.EnvServerIdleTimeoutSeconds, config.MaxServerIdleTimeoutSeconds, config.GetServerIdleTimeout},
		{config.EnvPoWChallengeTTLSeconds, config.MaxPoWChallengeTTLSeconds, config.GetPoWChallengeTTL},
	}
	for _, s := range settings {
		t.Run(s.key+" accepts its maximum", func(t *testing.T) {
			t.Setenv(s.key, strconv.Itoa(s.max))
			if err := validate(t); err != nil {
				t.Fatalf("%s=%d rejected: %v", s.key, s.max, err)
			}
			if got, want := s.read(), time.Duration(s.max)*time.Second; got != want {
				t.Fatalf("%s=%d read as %v, want %v", s.key, s.max, got, want)
			}
		})
		for _, seconds := range []int64{int64(s.max) + 1, maxUnwrapped, maxUnwrapped + 1, int64(s.max) + wrapPeriodSeconds} {
			value := strconv.FormatInt(seconds, 10)
			t.Run(s.key+" refuses "+value, func(t *testing.T) {
				t.Setenv(s.key, value)
				if got := s.read(); got != 0 {
					t.Fatalf("%s=%s read as %v, want 0 (refused)", s.key, value, got)
				}
				var f *opcode.Failure
				if err := validate(t); !errors.As(err, &f) || f.Code.ID != opcode.ConfigInvalid.ID {
					t.Fatalf("%s=%s: %v, want %s", s.key, value, err, opcode.ConfigInvalid.ID)
				}
			})
		}
	}
}

// The file settings default to the specified sizes, accept exactly their bounds (one part up to
// their maximum), and must nest: a file fits a conversation's quota, the quota the store, and a
// part upload the request body bound. A refusal names the setting that breaks the rule.
func TestValidateStartupConfig_FileLimits(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	for _, key := range []string{config.EnvMaxFileBytes, config.EnvFileConversationQuotaBytes, config.EnvFileStoreMaxBytes, config.EnvFileAccountDailyBytes} {
		t.Setenv(key, "")
	}
	if config.GetMaxFileBytes() != 10485760 || config.GetFileConversationQuotaBytes() != 104857600 || config.GetFileStoreMaxBytes() != 2147483648 || config.GetFileAccountDailyBytes() != 104857600 {
		t.Fatalf("defaults %d, %d, %d", config.GetMaxFileBytes(), config.GetFileConversationQuotaBytes(), config.GetFileStoreMaxBytes())
	}
	if err := validate(t); err != nil {
		t.Fatalf("the default file settings were refused: %v", err)
	}

	onePart := strconv.Itoa(utils.FilePartBytes)
	accepted := []map[string]string{
		{config.EnvMaxFileBytes: onePart, config.EnvFileConversationQuotaBytes: onePart, config.EnvFileStoreMaxBytes: onePart},
		{config.EnvMaxFileBytes: strconv.FormatInt(config.MaxFileBytesBound, 10)},
		{config.EnvFileConversationQuotaBytes: strconv.FormatInt(config.MaxFileConversationQuotaBound, 10),
			config.EnvFileStoreMaxBytes: strconv.FormatInt(config.MaxFileStoreBytesBound, 10)},
		{"MAX_REQUEST_BODY_BYTES": strconv.Itoa(2 * utils.FilePartSealedBytes)},
		{config.EnvFileAccountDailyBytes: strconv.FormatInt(config.MaxFileAccountDailyBound, 10)},
	}
	for _, settings := range accepted {
		t.Run("accepts "+describe(settings), func(t *testing.T) {
			for key, value := range settings {
				t.Setenv(key, value)
			}
			if err := validate(t); err != nil {
				t.Fatalf("refused: %v", err)
			}
		})
	}

	refused := []struct {
		settings map[string]string
		variable string
	}{
		{map[string]string{config.EnvMaxFileBytes: "104857600", config.EnvFileConversationQuotaBytes: "104857599"}, config.EnvMaxFileBytes},
		{map[string]string{config.EnvFileConversationQuotaBytes: "2147483649"}, config.EnvFileConversationQuotaBytes},
		{map[string]string{config.EnvFileStoreMaxBytes: onePart}, config.EnvFileConversationQuotaBytes},
		{map[string]string{"MAX_REQUEST_BODY_BYTES": strconv.Itoa(2*utils.FilePartSealedBytes - 1)}, "MAX_REQUEST_BODY_BYTES"},
		{map[string]string{config.EnvFileAccountDailyBytes: "10485759"}, config.EnvMaxFileBytes},
	}
	for _, c := range refused {
		t.Run("refuses "+describe(c.settings), func(t *testing.T) {
			for key, value := range c.settings {
				t.Setenv(key, value)
			}
			var f *opcode.Failure
			if err := validate(t); !errors.As(err, &f) || f.Code.ID != opcode.ConfigInvalid.ID || f.Variable != c.variable {
				t.Fatalf("got %v, want %s naming %s", err, opcode.ConfigInvalid.ID, c.variable)
			}
		})
	}
}

// describe names a set of settings for a subtest, in a fixed order.
func describe(settings map[string]string) string {
	pairs := make([]string, 0, len(settings))
	for key, value := range settings {
		pairs = append(pairs, key+"="+value)
	}
	sort.Strings(pairs)
	return strings.Join(pairs, ",")
}

// Production mode raises the floors: verified TLS to the database and a strong database password.
func TestValidateStartupConfig_ProductionFloors(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_SSL_MODE", "verify-full")
	t.Setenv("DB_PASSWORD", testutil.NewAuthKey(t))
	if err := validate(t); err != nil {
		t.Fatalf("hardened production configuration rejected: %v", err)
	}

	for name, c := range map[string][2]string{
		"plaintext database link":   {"DB_SSL_MODE", "disable"},
		"unauthenticated tls":       {"DB_SSL_MODE", "require"},
		"default database password": {"DB_PASSWORD", "postgres"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(c[0], c[1])
			if err := validate(t); err == nil {
				t.Errorf("production accepted %s=%s", c[0], c[1])
			}
		})
	}
}

// An https:// or .onion origin is a public instance: outside production its session cookie
// would lack Secure and the __Host- prefix and no production check would run, so startup
// refuses with E_CONFIG_INVALID naming APP_ENV (never the origin). Loopback http origins stay
// fine in development and test, and production accepts the public origins.
func TestValidateStartupConfig_PublicOriginNeedsProduction(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	public := []string{"https://chat.example.org", "http://localhost,https://chat.example.org:8443",
		"http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion", "http://ABCDEFGHIJKLMNOP.ONION",
		"http://abcdefghijklmnop.onion.", "https://[2001:db8::1]"}
	for _, mode := range []string{"development", "test", "Development"} {
		for _, origins := range public {
			t.Run(mode+" "+origins, func(t *testing.T) {
				t.Setenv("APP_ENV", mode)
				t.Setenv("ALLOWED_ORIGINS", origins)
				err := validate(t)
				var failure *opcode.Failure
				if !errors.As(err, &failure) || failure.Code != opcode.ConfigInvalid || failure.Variable != config.EnvAppEnv {
					t.Fatalf("APP_ENV=%s with ALLOWED_ORIGINS=%s: want E_CONFIG_INVALID naming APP_ENV, got %v", mode, origins, err)
				}
				if line := failure.Error(); strings.Contains(line, "example.org") || strings.Contains(strings.ToLower(line), "abcdefghijklmnop") {
					t.Fatalf("the refusal echoes an origin: %q", line)
				}
			})
		}
		for _, local := range []string{"http://localhost", "http://localhost:3000,http://127.0.0.1", "http://[::1]:8080", "http://chat.example.org"} {
			t.Setenv("APP_ENV", mode)
			t.Setenv("ALLOWED_ORIGINS", local)
			if err := validate(t); err != nil {
				t.Errorf("APP_ENV=%s refused ALLOWED_ORIGINS=%s: %v", mode, local, err)
			}
		}
	}

	t.Setenv("APP_ENV", "production")
	t.Setenv("DB_SSL_MODE", "verify-full")
	t.Setenv("DB_PASSWORD", testutil.NewAuthKey(t))
	for _, origins := range public {
		t.Setenv("ALLOWED_ORIGINS", origins)
		if err := validate(t); err != nil {
			t.Errorf("production refused ALLOWED_ORIGINS=%s: %v", origins, err)
		}
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
		{config.EnvMaxFileBytes, "leak-file-bytes", false},
		{config.EnvFileConversationQuotaBytes, "leak-file-quota", false},
		{config.EnvFileStoreMaxBytes, "leak-file-store", false},
		{config.EnvFileAccountDailyBytes, "leak-file-daily", false},
		{"POW_CHALLENGE_TTL_SEC", "leak-pow-ttl", false},
		{"POW_DIFFICULTY", "leak-pow-difficulty", false},
		{"INTERNAL_ID_LENGTH", "leak-id-length", false},
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
		{"DB_PASSWORD", "leak-pw", true},
	}
	for _, c := range cases {
		t.Run(c.variable+"="+c.value, func(t *testing.T) {
			if c.production {
				t.Setenv("APP_ENV", "production")
				t.Setenv("DB_SSL_MODE", "verify-full")
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
