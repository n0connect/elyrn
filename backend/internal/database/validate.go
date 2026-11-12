package database

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/config"
	"elyrn/internal/encryption"
	"elyrn/internal/utils"
)

// Startup validation is the one place every environment variable the server reads is checked
// (docs/operations/configuration-and-tuning.md lists each with its rule). The server refuses to
// start on any value outside its whitelist or range, with E_CONFIG_INVALID naming the variable
// and its rule, never its value. The checks run in a fixed order, so the first failing variable
// is the one reported.

// bounded is one numeric setting with its inclusive range (RULES.md §5.1: type, range,
// whitelist). Unparseable values read as 0 and fail the range check.
type bounded struct {
	key      string
	value    int
	min, max int
}

// invalid is the E_CONFIG_INVALID failure for variable with its rule.
func invalid(variable, rule string) error {
	return opcode.Fail(opcode.ConfigInvalid, variable, rule)
}

func checkBounds(settings []bounded) error {
	for _, s := range settings {
		if s.value < s.min || s.value > s.max {
			return invalid(s.key, fmt.Sprintf("must be an integer between %d and %d", s.min, s.max))
		}
	}
	return nil
}

func seconds(d time.Duration) int { return int(d / time.Second) }

// Whitelists. "off" (or "disabled") drops a cross-origin header; production keeps all three.
var (
	allowedAppEnvs   = map[string]struct{}{"development": {}, "test": {}, "production": {}, "prod": {}}
	allowedLogLevels = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	allowedSSLModes  = map[string]struct{}{"disable": {}, "allow": {}, "prefer": {}, "require": {}, "verify-ca": {}, "verify-full": {}}
	// Production must authenticate the database server, not just encrypt to whoever answers
	productionSSLModes = map[string]struct{}{"verify-ca": {}, "verify-full": {}}
	// Booleans as config.getEnvBool reads them: anything else would silently read as false
	allowedBooleans = map[string]struct{}{"true": {}, "false": {}, "1": {}, "0": {}, "yes": {}, "no": {}}
	headerOff       = map[string]struct{}{"off": {}, "disabled": {}}
	// Cross-origin header values a browser understands (Fetch and HTML standards)
	crossOriginHeaders = []struct {
		key     string
		allowed map[string]struct{}
	}{
		{"SEC_HEADER_COOP", map[string]struct{}{"same-origin": {}, "same-origin-allow-popups": {}, "unsafe-none": {}}},
		{"SEC_HEADER_CORP", map[string]struct{}{"same-origin": {}, "same-site": {}, "cross-origin": {}}},
		{"SEC_HEADER_COEP", map[string]struct{}{"require-corp": {}, "credentialless": {}, "unsafe-none": {}}},
	}
)

const (
	// minProductionDBPasswordLen rejects well-known defaults such as "postgres" in production
	minProductionDBPasswordLen = 16
	// maxHSTSMaxAge: two years, the longest max-age the preload list asks for
	maxHSTSMaxAge = 2 * 365 * 24 * 3600
	maxPort       = 65535
	// envSSLRootCert is libpq's (and pgx's) variable for the CA that verifies the database server
	envSSLRootCert = "PGSSLROOTCERT"
)

// ValidateStartupConfig validates all configuration at startup. A refusal is always an
// *opcode.Failure (E_CONFIG_INVALID, or what the master keys report).
func ValidateStartupConfig() error {
	if _, ok := allowedAppEnvs[strings.ToLower(strings.TrimSpace(config.GetEnv("APP_ENV", "development")))]; !ok {
		return invalid("APP_ENV", "must be one of development, test, production")
	}
	if _, ok := allowedLogLevels[config.GetLogLevel()]; !ok {
		return invalid("LOG_LEVEL", "must be one of debug, info, warn, error")
	}

	minJWTLen := config.GetJWTSecretMinLength()
	for _, check := range []func() error{
		func() error { return checkBounds(startupBounds(minJWTLen)) },
		func() error { return checkSecrets(minJWTLen) },
		checkSizesFit,
		checkConnections,
		checkHeaders,
	} {
		if err := check(); err != nil {
			return err
		}
	}
	if config.IsProductionMode() {
		return checkProduction()
	}
	return nil
}

// portNumber reads a port setting; a value that is not a number reads as 0 and fails its bound,
// whose rule already says "must be an integer between 1 and 65535".
func portNumber(raw string) int {
	port, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return port
}

// startupBounds is the range of every numeric setting. It holds data only, one row per
// setting, so it is kept as one linear table (RULES.md 7.1 exception for data initialization).
func startupBounds(minJWTLen int) []bounded {
	argon2Floor := config.MinArgon2MemoryKiB
	if config.IsProductionMode() {
		argon2Floor = config.ProductionMinArgon2MemoryKiB
	}
	return []bounded{
		{"JWT_SECRET_MIN_LEN", minJWTLen, 32, 1024},
		{"JWT_EXPIRATION_MINUTES", int(config.GetJWTExpiration() / time.Minute), 1, 1440},
		{"MAX_REQUEST_BODY_BYTES", config.GetMaxRequestBodyBytes(), 1024, 16 << 20},
		{"MAX_JSON_DEPTH", config.GetMaxJSONDepth(), 1, 8},
		{"INVITE_TTL_SEC", seconds(config.GetInviteTTL()), 60, 7 * 24 * 3600},
		{"MAX_ACTIVE_INVITES", config.GetMaxActiveInvites(), 1, 100},
		{"MAX_CONVERSATIONS_PER_USER", config.GetMaxConversationsPerUser(), 1, config.MaxConversationsPerUserBound},
		{"MAX_MESSAGE_BYTES", config.GetMaxMessageBytes(), 512, 65536},
		{"MESSAGE_PAGE_LIMIT", config.GetMessagePageLimit(), 1, 1000},
		{"MESSAGE_TTL_DAYS", config.GetMessageTTLDays(), 1, config.MaxMessageTTLDays()},
		{"ROOM_MAX_MEMBERS", config.GetRoomMaxMembers(), config.MinRoomMembers, config.MaxRoomMembersBound},
		{"ROOM_MAX_TTL_HOURS", config.GetRoomMaxTTLHours(), 1, config.MaxRoomTTLHoursBound},
		{"POW_CHALLENGE_TTL_SEC", seconds(config.GetPoWChallengeTTL()), 1, 3600},
		{"POW_DIFFICULTY", config.GetPoWDifficulty(), config.MinPoWDifficulty(), config.MaxPoWDifficulty()},
		{"INTERNAL_ID_LENGTH", config.GetInternalIDLength(), 16, 24}, // users.uuid is size:24
		{"ARGON2_MEMORY_KIB", config.GetArgon2MemoryKiB(), argon2Floor, config.MaxArgon2MemoryKiB},
		{"ARGON2_TIME", config.GetArgon2Time(), config.MinArgon2Time, config.MaxArgon2Time},
		{"ARGON2_PARALLELISM", config.GetArgon2Parallelism(), config.MinArgon2Parallelism, config.MaxArgon2Parallelism},
		{"ARGON2_SALT_LENGTH", config.GetArgon2SaltLength(), config.MinArgon2SaltBytes, config.MaxArgon2SaltBytes},
		{"ARGON2_HASH_LENGTH", config.GetArgon2HashLength(), config.MinArgon2HashBytes, config.MaxArgon2HashBytes},
		{"ARGON2_MAX_CONCURRENT", config.GetArgon2MaxConcurrent(), 1, 64},
		{"PENDING_TOKEN_TTL_SEC", seconds(config.GetPendingTokenTTL()), 30, 3600},
		{"PENDING_CLEANUP_INTERVAL_SEC", seconds(config.GetPendingCleanupInterval()), 1, 3600},
		{"PENDING_ID_BYTES", config.GetPendingIDBytes(), 16, 64},
		{"RATE_LIMIT_MAX_TOKENS", config.GetRateLimitMaxTokens(), 1, 10000},
		{"RATE_LIMIT_REFILL_INTERVAL_SEC", config.GetRateLimitRefillIntervalSeconds(), 1, 3600},
		{"RATE_LIMIT_CLEANUP_INTERVAL_SEC", config.GetRateLimitCleanupIntervalSeconds(), 1, 86400},
		{"RATE_LIMIT_MAX_BUCKETS", config.GetRateLimitMaxBuckets(), 100, 1000000},
		{"BACKEND_PORT", portNumber(config.GetBackendPort()), 1, maxPort},
		{"DB_PORT", portNumber(config.GetDBPort()), 1, maxPort},
		{"SERVER_READ_HEADER_TIMEOUT_SEC", seconds(config.GetServerReadHeaderTimeout()), 1, 60},
		{"SERVER_READ_TIMEOUT_SEC", seconds(config.GetServerReadTimeout()), 1, 300},
		{"SERVER_WRITE_TIMEOUT_SEC", seconds(config.GetServerWriteTimeout()), 1, 300},
		{"SERVER_IDLE_TIMEOUT_SEC", seconds(config.GetServerIdleTimeout()), 1, 600},
		{"SERVER_MAX_HEADER_BYTES", config.GetServerMaxHeaderBytes(), 1024, 1 << 20},
	}
}

// checkSecrets insists on the signing secret, the token claims, the master keys and the pepper.
func checkSecrets(minJWTLen int) error {
	if len(config.GetJWTSecret()) < minJWTLen {
		return invalid("JWT_SECRET", fmt.Sprintf("must be at least %d characters (generate it: openssl rand -hex 32)", minJWTLen))
	}
	if config.GetJWTIssuer() == "" {
		return invalid("JWT_ISSUER", "is required")
	}
	if config.GetJWTAudience() == "" {
		return invalid("JWT_AUDIENCE", "is required")
	}
	if err := encryption.InitMasterKeys(); err != nil {
		return err
	}
	if config.GetAccountLookupPepper() == nil {
		return invalid("ACCOUNT_LOOKUP_PEPPER", "must be at least 32 bytes as hex or base64 (generate it: openssl rand -hex 32)")
	}
	return nil
}

// checkSizesFit insists that the largest message, direct or to a full room, fits a request body.
func checkSizesFit() error {
	if config.GetMaxMessageBytes() > config.GetMaxRequestBodyBytes()/2 {
		return invalid("MAX_MESSAGE_BYTES", "must fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}
	if utils.RoomMaxBlobBytes(config.GetRoomMaxMembers()) > config.GetMaxRequestBodyBytes()/2 {
		return invalid("ROOM_MAX_MEMBERS", "a message to a full room must fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}
	return nil
}

// checkConnections insists on a complete database address, a libpq sslmode with its CA, exact
// origins and parseable trusted proxies.
func checkConnections() error {
	for _, required := range []struct{ key, value string }{
		{"DB_HOST", config.GetDBHost()}, {"DB_USER", config.GetDBUser()},
		{"DB_PASSWORD", config.GetDBPassword()}, {"DB_NAME", config.GetDBName()},
	} {
		if required.value == "" {
			return invalid(required.key, "is required")
		}
	}
	if _, ok := allowedSSLModes[config.GetDBSSLMode()]; !ok {
		return invalid("DB_SSL_MODE", "must be a libpq sslmode (disable, require, verify-ca, verify-full, ...)")
	}
	if err := checkRootCert(); err != nil {
		return err
	}
	if _, err := utils.ParseOrigins(config.GetAllowedOrigins()); err != nil {
		return invalid("ALLOWED_ORIGINS", "must list exact origins scheme://host[:port], comma-separated, no wildcard or path ("+err.Error()+")")
	}
	if _, _, err := utils.ParseProxyList(config.GetTrustedProxies()); err != nil {
		return invalid("TRUSTED_PROXIES", "must list IP addresses or CIDR ranges, comma-separated ("+err.Error()+")")
	}
	return nil
}

// checkRootCert: when set, PGSSLROOTCERT must be a readable file holding at least one PEM
// certificate. Unset, the driver falls back to the system roots (verify-*) or verifies nothing.
func checkRootCert() error {
	path := strings.TrimSpace(os.Getenv(envSSLRootCert))
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return invalid(envSSLRootCert, "must name a readable file (make certs writes certs/ca/ca.crt)")
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return invalid(envSSLRootCert, "must hold a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return invalid(envSSLRootCert, "must hold a PEM certificate")
	}
	return nil
}

// checkHeaders: the HSTS settings and the cross-origin headers are whitelisted, so a typo never
// reads as "off" (a malformed HSTS_MAX_AGE used to read as 0, i.e. no HSTS at all).
func checkHeaders() error {
	if raw := strings.TrimSpace(os.Getenv("HSTS_MAX_AGE")); raw != "" {
		if age, err := strconv.Atoi(raw); err != nil || age < 0 || age > maxHSTSMaxAge {
			return invalid("HSTS_MAX_AGE", fmt.Sprintf("must be an integer between 0 and %d seconds", maxHSTSMaxAge))
		}
	}
	for _, key := range []string{"HSTS_INCLUDE_SUBDOMAINS", "HSTS_PRELOAD"} {
		if raw := strings.ToLower(strings.TrimSpace(os.Getenv(key))); raw != "" {
			if _, ok := allowedBooleans[raw]; !ok {
				return invalid(key, "must be true or false")
			}
		}
	}
	for _, header := range crossOriginHeaders {
		raw := strings.ToLower(strings.TrimSpace(os.Getenv(header.key)))
		if raw == "" {
			continue
		}
		_, known := header.allowed[raw]
		_, off := headerOff[raw]
		if !known && !off {
			return invalid(header.key, "must be a value browsers understand, or off")
		}
		if off && config.IsProductionMode() {
			return invalid(header.key, "must not be off in production")
		}
	}
	return nil
}

// checkProduction adds what production demands beyond the ranges: an authenticated database,
// a strong database password and no debug logging.
func checkProduction() error {
	if _, ok := productionSSLModes[config.GetDBSSLMode()]; !ok {
		return invalid("DB_SSL_MODE", "must be verify-ca or verify-full in production")
	}
	if len(config.GetDBPassword()) < minProductionDBPasswordLen {
		return invalid("DB_PASSWORD", fmt.Sprintf("must be at least %d characters in production", minProductionDBPasswordLen))
	}
	if config.GetTrustedProxies() == "" {
		dbLogger.Warn("TRUSTED_PROXIES is empty: behind a reverse proxy every client shares one rate-limit bucket")
	}
	if config.GetLogLevel() == "debug" {
		return invalid("LOG_LEVEL", "must not be debug in production")
	}
	dbLogger.Info("Production mode validation passed")
	return nil
}
