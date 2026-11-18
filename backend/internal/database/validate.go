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
// whitelist). Unparseable values read as 0 and fail the range check. Most settings are int; the
// file sizes are int64 (config: their bounds do not fit a 32-bit int).
type bounded[T int | int64] struct {
	key      string
	value    T
	min, max T
}

// invalid is the E_CONFIG_INVALID failure for variable with its rule.
func invalid(variable, rule string) error {
	return opcode.Fail(opcode.ConfigInvalid, variable, rule)
}

func checkBounds[T int | int64](settings []bounded[T]) error {
	for _, s := range settings {
		if s.value < s.min || s.value > s.max {
			return invalid(s.key, fmt.Sprintf("must be an integer between %d and %d", s.min, s.max))
		}
	}
	return nil
}

func seconds(d time.Duration) int { return int(d / time.Second) }

// Whitelists
var (
	allowedAppEnvs   = map[string]struct{}{"development": {}, "test": {}, "production": {}, "prod": {}}
	allowedLogLevels = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	allowedSSLModes  = map[string]struct{}{"disable": {}, "allow": {}, "prefer": {}, "require": {}, "verify-ca": {}, "verify-full": {}}
	// Production must authenticate the database server, not just encrypt to whoever answers
	productionSSLModes = map[string]struct{}{"verify-ca": {}, "verify-full": {}}
)

const (
	// minProductionDBPasswordLen rejects well-known defaults such as "postgres" in production
	minProductionDBPasswordLen = 16
	minPort                    = 1
	maxPort                    = 65535
	// minCount is the floor of every count, size and interval setting: at least one
	minCount = 1
	// wireExpansion: twice a raw size covers its base64 and the JSON around it in a request body
	wireExpansion = 2
	// envSSLRootCert is libpq's (and pgx's) variable for the CA that verifies the database server
	envSSLRootCert = "PGSSLROOTCERT"
)

// ValidateStartupConfig validates all configuration at startup. A refusal is always an
// *opcode.Failure (E_CONFIG_INVALID, or what the master keys report).
func ValidateStartupConfig() error {
	if _, ok := allowedAppEnvs[config.GetAppEnv()]; !ok {
		return invalid(config.EnvAppEnv, "must be one of development, test, production")
	}
	if _, ok := allowedLogLevels[config.GetLogLevel()]; !ok {
		return invalid(config.EnvLogLevel, "must be one of debug, info, warn, error")
	}

	minJWTLen := config.GetJWTSecretMinLength()
	for _, check := range []func() error{
		func() error { return checkBounds(startupBounds(minJWTLen)) },
		func() error { return checkBounds(fileBounds()) },
		func() error { return checkSecrets(minJWTLen) },
		checkSizesFit,
		checkConnections,
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
func startupBounds(minJWTLen int) []bounded[int] {
	return []bounded[int]{
		{config.EnvJWTSecretMinLen, minJWTLen, config.MinJWTSecretMinLen, config.MaxJWTSecretMinLen},
		{config.EnvJWTExpirationMinutes, int(config.GetJWTExpiration() / time.Minute), config.MinJWTExpirationMinutes, config.MaxJWTExpirationMinutes},
		{config.EnvMaxRequestBodyBytes, config.GetMaxRequestBodyBytes(), config.MinRequestBodyBytes, config.MaxRequestBodyBytesBound},
		{config.EnvMaxJSONDepth, config.GetMaxJSONDepth(), minCount, config.MaxJSONDepthBound},
		{config.EnvInviteTTLSeconds, seconds(config.GetInviteTTL()), config.MinInviteTTLSeconds, config.MaxInviteTTLSeconds},
		{config.EnvMaxActiveInvites, config.GetMaxActiveInvites(), minCount, config.MaxActiveInvitesBound},
		{config.EnvMaxConversationsPerUser, config.GetMaxConversationsPerUser(), minCount, config.MaxConversationsPerUserBound},
		{config.EnvMaxMessageBytes, config.GetMaxMessageBytes(), config.MinMessageBytes, config.MaxMessageBytesBound},
		{config.EnvMessagePageLimit, config.GetMessagePageLimit(), minCount, config.MaxMessagePageLimitBound},
		{config.EnvMessageTTLDays, config.GetMessageTTLDays(), minCount, config.MaxMessageTTLDays()},
		{config.EnvRoomMaxMembers, config.GetRoomMaxMembers(), config.MinRoomMembers, config.MaxRoomMembersBound},
		{config.EnvRoomMaxTTLHours, config.GetRoomMaxTTLHours(), config.MinRoomTTLHours, config.MaxRoomTTLHoursBound},
		{config.EnvPoWChallengeTTLSeconds, seconds(config.GetPoWChallengeTTL()), minCount, config.MaxPoWChallengeTTLSeconds},
		{config.EnvPoWDifficulty, config.GetPoWDifficulty(), config.MinPoWDifficulty(), config.MaxPoWDifficulty()},
		{config.EnvInternalIDLength, config.GetInternalIDLength(), config.MinInternalIDLength, config.MaxInternalIDLength},
		{config.EnvPendingTokenTTLSeconds, seconds(config.GetPendingTokenTTL()), config.MinPendingTokenTTLSeconds, config.MaxPendingTokenTTLSeconds},
		{config.EnvPendingCleanupIntervalSeconds, seconds(config.GetPendingCleanupInterval()), minCount, config.MaxPendingCleanupSeconds},
		{config.EnvPendingIDBytes, config.GetPendingIDBytes(), config.MinPendingIDBytes, config.MaxPendingIDBytes},
		{config.EnvRateLimitMaxTokens, config.GetRateLimitMaxTokens(), minCount, config.MaxRateLimitTokensBound},
		{config.EnvRateLimitRefillIntervalSeconds, config.GetRateLimitRefillIntervalSeconds(), minCount, config.MaxRateLimitRefillSeconds},
		{config.EnvRateLimitCleanupIntervalSeconds, config.GetRateLimitCleanupIntervalSeconds(), minCount, config.MaxRateLimitCleanupSeconds},
		{config.EnvRateLimitMaxBuckets, config.GetRateLimitMaxBuckets(), config.MinRateLimitBuckets, config.MaxRateLimitBucketsBound},
		{config.EnvBackendPort, portNumber(config.GetBackendPort()), minPort, maxPort},
		{config.EnvDBPort, portNumber(config.GetDBPort()), minPort, maxPort},
		{config.EnvServerReadHeaderTimeoutSeconds, seconds(config.GetServerReadHeaderTimeout()), minCount, config.MaxServerReadHeaderTimeoutSeconds},
		{config.EnvServerReadTimeoutSeconds, seconds(config.GetServerReadTimeout()), minCount, config.MaxServerReadTimeoutSeconds},
		{config.EnvServerWriteTimeoutSeconds, seconds(config.GetServerWriteTimeout()), minCount, config.MaxServerWriteTimeoutSeconds},
		{config.EnvServerIdleTimeoutSeconds, seconds(config.GetServerIdleTimeout()), minCount, config.MaxServerIdleTimeoutSeconds},
		{config.EnvServerMaxHeaderBytes, config.GetServerMaxHeaderBytes(), config.MinServerMaxHeaderBytes, config.MaxServerMaxHeaderBytesBound},
	}
}

// fileBounds is the range of every file setting, each at least one stored part.
func fileBounds() []bounded[int64] {
	return []bounded[int64]{
		{config.EnvMaxFileBytes, config.GetMaxFileBytes(), utils.FilePartBytes, config.MaxFileBytesBound},
		{config.EnvFileConversationQuotaBytes, config.GetFileConversationQuotaBytes(), utils.FilePartBytes, config.MaxFileConversationQuotaBound},
		{config.EnvFileStoreMaxBytes, config.GetFileStoreMaxBytes(), utils.FilePartBytes, config.MaxFileStoreBytesBound},
		{config.EnvFileAccountDailyBytes, config.GetFileAccountDailyBytes(), utils.FilePartBytes, config.MaxFileAccountDailyBound},
	}
}

// checkSecrets insists on the signing secret, the token claims, the master keys and the pepper.
func checkSecrets(minJWTLen int) error {
	if len(config.GetJWTSecret()) < minJWTLen {
		return invalid(config.EnvJWTSecret, fmt.Sprintf("must be at least %d characters (generate it: openssl rand -hex 32)", minJWTLen))
	}
	if config.GetJWTIssuer() == "" {
		return invalid(config.EnvJWTIssuer, "is required")
	}
	if config.GetJWTAudience() == "" {
		return invalid(config.EnvJWTAudience, "is required")
	}
	if err := encryption.InitMasterKeys(); err != nil {
		return err
	}
	if config.GetAccountLookupPepper() == nil {
		return invalid(config.EnvAccountLookupPepper, fmt.Sprintf("must be at least %d bytes as hex or base64 (generate it: openssl rand -hex 32)", config.MinPepperBytes()))
	}
	return nil
}

// checkSizesFit insists that the largest message, direct or to a full room, and a file part fit
// a request body, and that a file fits a conversation's quota and that quota the store.
func checkSizesFit() error {
	if config.GetMaxMessageBytes() > config.GetMaxRequestBodyBytes()/wireExpansion {
		return invalid(config.EnvMaxMessageBytes, "must fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}
	if utils.RoomMaxBlobBytes(config.GetRoomMaxMembers()) > config.GetMaxRequestBodyBytes()/wireExpansion {
		return invalid(config.EnvRoomMaxMembers, "a message to a full room must fit (base64) inside MAX_REQUEST_BODY_BYTES")
	}
	// The same rule as a message: twice the raw size covers base64 and the JSON around it
	if utils.FilePartSealedBytes > config.GetMaxRequestBodyBytes()/wireExpansion {
		return invalid(config.EnvMaxRequestBodyBytes, fmt.Sprintf("must hold a file part upload (at least %d bytes)", wireExpansion*utils.FilePartSealedBytes))
	}
	if config.GetMaxFileBytes() > config.GetFileConversationQuotaBytes() {
		return invalid(config.EnvMaxFileBytes, "must not exceed "+config.EnvFileConversationQuotaBytes)
	}
	if config.GetFileConversationQuotaBytes() > config.GetFileStoreMaxBytes() {
		return invalid(config.EnvFileConversationQuotaBytes, "must not exceed "+config.EnvFileStoreMaxBytes)
	}
	if config.GetMaxFileBytes() > config.GetFileAccountDailyBytes() {
		return invalid(config.EnvMaxFileBytes, "must not exceed "+config.EnvFileAccountDailyBytes)
	}
	return nil
}

// checkConnections insists on a complete database address, a libpq sslmode with its CA, exact
// origins and parseable trusted proxies.
func checkConnections() error {
	for _, required := range []struct{ key, value string }{
		{config.EnvDBHost, config.GetDBHost()}, {config.EnvDBUser, config.GetDBUser()},
		{config.EnvDBPassword, config.GetDBPassword()}, {config.EnvDBName, config.GetDBName()},
	} {
		if required.value == "" {
			return invalid(required.key, "is required")
		}
	}
	if _, ok := allowedSSLModes[config.GetDBSSLMode()]; !ok {
		return invalid(config.EnvDBSSLMode, "must be a libpq sslmode (disable, require, verify-ca, verify-full, ...)")
	}
	if err := checkRootCert(); err != nil {
		return err
	}
	if _, err := utils.ParseOrigins(config.GetAllowedOrigins()); err != nil {
		return invalid(config.EnvAllowedOrigins, "must list exact origins scheme://host[:port], comma-separated, no wildcard or path ("+err.Error()+")")
	}
	if _, _, err := utils.ParseProxyList(config.GetTrustedProxies()); err != nil {
		return invalid(config.EnvTrustedProxies, fmt.Sprintf("must list IP addresses or CIDR ranges of at least /%d (IPv4) or /%d (IPv6), comma-separated (%s)",
			utils.MinProxyPrefixIPv4, utils.MinProxyPrefixIPv6, err.Error()))
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
	// The second result is the bytes after the first block, not an error: the first certificate
	// proves the file is a PEM bundle; the driver reads the rest
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return invalid(envSSLRootCert, "must hold a PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return invalid(envSSLRootCert, "must hold a PEM certificate")
	}
	return nil
}

// checkProduction adds what production demands beyond the ranges: an authenticated database,
// a strong database password and no debug logging.
func checkProduction() error {
	if _, ok := productionSSLModes[config.GetDBSSLMode()]; !ok {
		return invalid(config.EnvDBSSLMode, "must be verify-ca or verify-full in production")
	}
	if len(config.GetDBPassword()) < minProductionDBPasswordLen {
		return invalid(config.EnvDBPassword, fmt.Sprintf("must be at least %d characters in production", minProductionDBPasswordLen))
	}
	if config.GetTrustedProxies() == "" {
		dbLogger.Warn("TRUSTED_PROXIES is empty: behind a reverse proxy every client shares one rate-limit bucket")
	}
	if config.GetLogLevel() == "debug" {
		return invalid(config.EnvLogLevel, "must not be debug in production")
	}
	dbLogger.Info("Production mode validation passed")
	return nil
}
