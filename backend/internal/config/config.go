package config

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultJWTSecretMinLen = 32
	// The "noaddx" issuer, audience and database defaults are stored names kept across the rename to elyrn.
	defaultJWTIssuer               = "noaddx-backend"
	defaultJWTAudience             = "noaddx-web"
	defaultJWTExpirationMinutes    = 30 * 24 * 60 // 30 days: with the sliding refresh a session in use never ends
	defaultAllowedOrigins          = "http://localhost"
	defaultAppEnv                  = "development"
	defaultLogLevel                = "info"
	defaultDBHost                  = "postgres"
	defaultDBPort                  = "5432"
	defaultDBUser                  = "postgres"
	defaultDBName                  = "noaddx"
	defaultDBSSLMode               = "disable"
	defaultBackendPort             = "8080"
	defaultMaxRequestBodyBytes     = 1048576
	defaultMaxJSONDepth            = 2
	defaultInviteTTLSeconds        = 86400 // Pairing tickets die after 24h
	defaultMaxActiveInvites        = 5
	defaultMaxConversationsPerUser = 256
	defaultMaxMessageBytes         = 8192 // Raw E2E ciphertext (nonce + payload + tag)
	defaultMessagePageLimit        = 200
	defaultMessageTTLDays          = 7 // Messages vanish after TTL..TTL+1 days (day-granular)
	maxMessageTTLDays              = 365
	defaultRoomMaxMembers          = 16
	defaultRoomMaxTTLHours         = 168 // A room lives at most a week by default
	// Argon2id parameters follow OWASP recommendations (2023)
	// Memory: 64MiB (65536 KiB) - recommended for password hashing
	// Time: 3 iterations - balance between security and performance
	// Parallelism: 4 - utilize multi-core CPUs effectively
	// Note: These defaults are tuned for production with 100-200 concurrent users
	// High-traffic scenarios (1000+ concurrent) may need adjustment or queueing
	defaultArgon2MemoryKiB   = 65536
	defaultArgon2Time        = 3
	defaultArgon2Parallelism = 4 // Increased from 2 for better CPU utilization
	defaultArgon2SaltLength  = 16
	defaultArgon2HashLength  = 32
	// At most this many Argon2id computations at once (each takes ARGON2_MEMORY_KIB)
	defaultArgon2MaxConcurrent     = 4
	defaultPendingTokenTTLSeconds  = 300
	defaultPendingCleanupSeconds   = 60
	defaultPendingIDBytes          = 16
	defaultInternalIDLength        = 24
	defaultRateLimitMaxTokens      = 20
	defaultRateLimitRefillSeconds  = 3
	defaultRateLimitCleanupSeconds = 300
	defaultRateLimitMaxBuckets     = 10000
	defaultServerReadHeaderTimeout = 5
	defaultServerReadTimeout       = 15
	defaultServerWriteTimeout      = 15
	defaultServerIdleTimeout       = 60
	defaultServerMaxHeaderBytes    = 8192
	defaultPoWDifficulty           = 20  // Strong security with acceptable browser performance (~20-40 sec)
	minPoWDifficulty               = 18  // Minimum difficulty (low load)
	maxPoWDifficulty               = 24  // Maximum difficulty (high load, DoS protection)
	defaultPoWChallengeTTLSeconds  = 300 // A challenge must be solved and used within 5 minutes
	MaxPoWChallengeTTLSeconds      = 3600
	minPepperBytes                 = 32
)

// Argon2id bounds (RULES.md §5.1 range checks). They apply to configuration at startup and
// to every stored hash before verification, so no record can request unbounded work.
const (
	MinArgon2MemoryKiB           = 8192    // 8 MiB: test floor; production requires ProductionMinArgon2MemoryKiB
	MaxArgon2MemoryKiB           = 1 << 20 // 1 GiB
	MinArgon2Time                = 1
	MaxArgon2Time                = 16
	MinArgon2Parallelism         = 1
	MaxArgon2Parallelism         = 255 // argon2 takes uint8 lanes
	MinArgon2SaltBytes           = 16
	MaxArgon2SaltBytes           = 64
	MinArgon2HashBytes           = 16
	MaxArgon2HashBytes           = 64
	ProductionMinArgon2MemoryKiB = 19456 // OWASP minimum for Argon2id (19 MiB, t=2)
)

// Setting names: the environment variable each getter reads, also the name startup validation
// reports a refused value under.
const (
	EnvJWTSecret                       = "JWT_SECRET"
	EnvJWTSecretMinLen                 = "JWT_SECRET_MIN_LEN"
	EnvJWTIssuer                       = "JWT_ISSUER"
	EnvJWTAudience                     = "JWT_AUDIENCE"
	EnvJWTExpirationMinutes            = "JWT_EXPIRATION_MINUTES"
	EnvMaxRequestBodyBytes             = "MAX_REQUEST_BODY_BYTES"
	EnvMaxJSONDepth                    = "MAX_JSON_DEPTH"
	EnvInviteTTLSeconds                = "INVITE_TTL_SEC"
	EnvMaxActiveInvites                = "MAX_ACTIVE_INVITES"
	EnvMaxConversationsPerUser         = "MAX_CONVERSATIONS_PER_USER"
	EnvRoomMaxMembers                  = "ROOM_MAX_MEMBERS"
	EnvRoomMaxTTLHours                 = "ROOM_MAX_TTL_HOURS"
	EnvMaxMessageBytes                 = "MAX_MESSAGE_BYTES"
	EnvMessagePageLimit                = "MESSAGE_PAGE_LIMIT"
	EnvMessageTTLDays                  = "MESSAGE_TTL_DAYS"
	EnvAllowedOrigins                  = "ALLOWED_ORIGINS"
	EnvAppEnv                          = "APP_ENV"
	EnvLogLevel                        = "LOG_LEVEL"
	EnvTrustedProxies                  = "TRUSTED_PROXIES"
	EnvRateLimitMaxTokens              = "RATE_LIMIT_MAX_TOKENS"
	EnvRateLimitRefillIntervalSeconds  = "RATE_LIMIT_REFILL_INTERVAL_SEC"
	EnvRateLimitCleanupIntervalSeconds = "RATE_LIMIT_CLEANUP_INTERVAL_SEC"
	EnvRateLimitMaxBuckets             = "RATE_LIMIT_MAX_BUCKETS"
	EnvDBHost                          = "DB_HOST"
	EnvDBPort                          = "DB_PORT"
	EnvDBUser                          = "DB_USER"
	EnvDBPassword                      = "DB_PASSWORD"
	EnvDBName                          = "DB_NAME"
	EnvDBSSLMode                       = "DB_SSL_MODE"
	EnvArgon2MemoryKiB                 = "ARGON2_MEMORY_KIB"
	EnvArgon2Time                      = "ARGON2_TIME"
	EnvArgon2Parallelism               = "ARGON2_PARALLELISM"
	EnvArgon2MaxConcurrent             = "ARGON2_MAX_CONCURRENT"
	EnvArgon2SaltLength                = "ARGON2_SALT_LENGTH"
	EnvArgon2HashLength                = "ARGON2_HASH_LENGTH"
	EnvAccountLookupPepper             = "ACCOUNT_LOOKUP_PEPPER"
	EnvPendingTokenTTLSeconds          = "PENDING_TOKEN_TTL_SEC"
	EnvPendingCleanupIntervalSeconds   = "PENDING_CLEANUP_INTERVAL_SEC"
	EnvPendingIDBytes                  = "PENDING_ID_BYTES"
	EnvInternalIDLength                = "INTERNAL_ID_LENGTH"
	EnvBackendPort                     = "BACKEND_PORT"
	EnvServerReadHeaderTimeoutSeconds  = "SERVER_READ_HEADER_TIMEOUT_SEC"
	EnvServerReadTimeoutSeconds        = "SERVER_READ_TIMEOUT_SEC"
	EnvServerWriteTimeoutSeconds       = "SERVER_WRITE_TIMEOUT_SEC"
	EnvServerIdleTimeoutSeconds        = "SERVER_IDLE_TIMEOUT_SEC"
	EnvServerMaxHeaderBytes            = "SERVER_MAX_HEADER_BYTES"
	EnvPoWDifficulty                   = "POW_DIFFICULTY"
	EnvPoWChallengeTTLSeconds          = "POW_CHALLENGE_TTL_SEC"
	EnvMasterKeyActive                 = "MASTER_KEY_ACTIVE"
	EnvMasterKeyActiveID               = "MASTER_KEY_ACTIVE_ID"
	EnvMasterKeyOld                    = "MASTER_KEY_OLD"
)

// Ranges accepted at startup (database.ValidateStartupConfig) for the settings whose getter
// does not need its own bound; the bounds a getter applies are declared beside it.
const (
	MinJWTSecretMinLen = 32
	MaxJWTSecretMinLen = 1024

	MinRequestBodyBytes      = 1024
	MaxRequestBodyBytesBound = 16 << 20
	MaxJSONDepthBound        = 8

	MinInviteTTLSeconds   = 60
	MaxInviteTTLSeconds   = 7 * 24 * 3600
	MaxActiveInvitesBound = 100

	MinMessageBytes          = 512
	MaxMessageBytesBound     = 65536
	MaxMessagePageLimitBound = 1000

	// MinInternalIDLength and MaxInternalIDLength: users.uuid is size:24
	MinInternalIDLength = 16
	MaxInternalIDLength = 24

	MaxArgon2ConcurrentBound = 64

	MinPendingTokenTTLSeconds = 30
	MaxPendingTokenTTLSeconds = 3600
	MaxPendingCleanupSeconds  = 3600
	MinPendingIDBytes         = 16
	MaxPendingIDBytes         = 64

	MaxRateLimitTokensBound    = 10000
	MaxRateLimitRefillSeconds  = 3600
	MaxRateLimitCleanupSeconds = 86400
	MinRateLimitBuckets        = 100
	MaxRateLimitBucketsBound   = 1000000

	MaxServerReadHeaderTimeoutSeconds = 60
	MaxServerReadTimeoutSeconds       = 300
	MaxServerWriteTimeoutSeconds      = 300
	MaxServerIdleTimeoutSeconds       = 600
	MinServerMaxHeaderBytes           = 1024
	MaxServerMaxHeaderBytesBound      = 1 << 20
)

// ========================================
// ENVIRONMENT VARIABLE HELPERS
// ========================================

func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntDefault(key string, defaultValue int) int {
	value := strings.TrimSpace(GetEnv(key, ""))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

// getEnvSecondsDefault reads a whole-seconds setting as a duration. The count is range-checked
// as an integer first: anything that is not a positive integer up to maxSeconds reads as 0
// (refused at startup), so a huge count can never wrap time.Duration into an accepted value.
func getEnvSecondsDefault(key string, defaultSeconds, maxSeconds int) time.Duration {
	seconds := getEnvIntDefault(key, defaultSeconds)
	if seconds <= 0 || seconds > maxSeconds {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// ========================================
// JWT CONFIGURATION
// ========================================

// GetJWTSecret returns JWT secret key from environment
func GetJWTSecret() string {
	return GetEnv(EnvJWTSecret, "")
}

// GetJWTSecretMinLength returns minimum JWT secret length in characters
func GetJWTSecretMinLength() int {
	return getEnvIntDefault(EnvJWTSecretMinLen, defaultJWTSecretMinLen)
}

// GetJWTIssuer returns JWT issuer value
func GetJWTIssuer() string {
	return strings.TrimSpace(GetEnv(EnvJWTIssuer, defaultJWTIssuer))
}

// GetJWTAudience returns JWT audience value
func GetJWTAudience() string {
	return strings.TrimSpace(GetEnv(EnvJWTAudience, defaultJWTAudience))
}

// Session lifetime accepted at startup (JWT_EXPIRATION_MINUTES).
const (
	// MinJWTExpirationMinutes: a session must outlive at least one request round
	MinJWTExpirationMinutes = 1
	// MaxJWTExpirationMinutes: 365 days; logout and account deletion revoke sooner (session_epoch)
	MaxJWTExpirationMinutes = 365 * 24 * 60
)

// GetJWTExpiration returns JWT token expiration duration. A value above
// MaxJWTExpirationMinutes reads as 0 (refused at startup) before it can overflow time.Duration.
func GetJWTExpiration() time.Duration {
	minutes := getEnvIntDefault(EnvJWTExpirationMinutes, defaultJWTExpirationMinutes)
	if minutes <= 0 || minutes > MaxJWTExpirationMinutes {
		return 0
	}
	return time.Duration(minutes) * time.Minute
}

// ========================================
// REQUEST AND VALIDATION LIMITS
// ========================================

// GetMaxRequestBodyBytes returns max request body size in bytes
func GetMaxRequestBodyBytes() int {
	return getEnvIntDefault(EnvMaxRequestBodyBytes, defaultMaxRequestBodyBytes)
}

// GetMaxJSONDepth returns max JSON nesting depth
func GetMaxJSONDepth() int {
	return getEnvIntDefault(EnvMaxJSONDepth, defaultMaxJSONDepth)
}

// ========================================
// MESSAGING CONFIGURATION
// ========================================

// GetInviteTTL returns how long an unredeemed invite stays valid
func GetInviteTTL() time.Duration {
	return getEnvSecondsDefault(EnvInviteTTLSeconds, defaultInviteTTLSeconds, MaxInviteTTLSeconds)
}

// GetMaxActiveInvites returns the cap on unredeemed invites per user
func GetMaxActiveInvites() int {
	return getEnvIntDefault(EnvMaxActiveInvites, defaultMaxActiveInvites)
}

// MaxConversationsPerUserBound is the highest MAX_CONVERSATIONS_PER_USER accepted. Stored
// conversation indexes are read up to this bound, not the current setting, so lowering the
// setting only stops new conversations and never locks an account out of its own.
const MaxConversationsPerUserBound = 4096

// GetMaxConversationsPerUser returns the cap on conversations per user
func GetMaxConversationsPerUser() int {
	return getEnvIntDefault(EnvMaxConversationsPerUser, defaultMaxConversationsPerUser)
}

// Room limits accepted at startup: a room message carries one 48-byte wrap per member, so the
// member bound also bounds its size (RoomMaxBlobBytes).
const (
	MinRoomMembers       = 2
	MaxRoomMembersBound  = 32
	MinRoomTTLHours      = 1
	MaxRoomTTLHoursBound = 720
	// RoomExpiryRoundHours: a creator rounds a room's expiry up past the current hour by this many
	RoomExpiryRoundHours = 1
)

// GetRoomMaxMembers returns the largest room a member may create
func GetRoomMaxMembers() int {
	return getEnvIntDefault(EnvRoomMaxMembers, defaultRoomMaxMembers)
}

// GetRoomMaxTTLHours returns the longest lifetime a room may be created with
func GetRoomMaxTTLHours() int {
	return getEnvIntDefault(EnvRoomMaxTTLHours, defaultRoomMaxTTLHours)
}

// GetMaxMessageBytes returns the max raw ciphertext size of one message
func GetMaxMessageBytes() int {
	return getEnvIntDefault(EnvMaxMessageBytes, defaultMaxMessageBytes)
}

// GetMessagePageLimit returns the max number of messages returned per request
func GetMessagePageLimit() int {
	return getEnvIntDefault(EnvMessagePageLimit, defaultMessagePageLimit)
}

// GetMessageTTLDays returns how many days ciphertext is kept before deletion
func GetMessageTTLDays() int {
	return getEnvIntDefault(EnvMessageTTLDays, defaultMessageTTLDays)
}

// MaxMessageTTLDays is the upper bound accepted for MESSAGE_TTL_DAYS
func MaxMessageTTLDays() int {
	return maxMessageTTLDays
}

// File settings: their names (startup validation reports them), the upper bound of each (the
// floor, one stored part, is utils.FilePartBytes: this package sits below utils) and defaults.
// int64: the quota and store bounds do not fit a 32-bit int, and this package is compiled into
// the agent for every target.
const (
	EnvMaxFileBytes               = "MAX_FILE_BYTES"
	EnvFileConversationQuotaBytes = "FILE_CONVERSATION_QUOTA_BYTES"
	EnvFileStoreMaxBytes          = "FILE_STORE_MAX_BYTES"
	EnvFileAccountDailyBytes      = "FILE_ACCOUNT_DAILY_BYTES"

	MaxFileBytesBound             int64 = 100 << 20 // 104857600
	MaxFileConversationQuotaBound int64 = 10 << 30  // 10737418240
	MaxFileStoreBytesBound        int64 = 1 << 40   // 1099511627776
	MaxFileAccountDailyBound      int64 = 10 << 30  // 10737418240

	defaultMaxFileBytes          int64 = 10 << 20  // 10485760
	defaultFileConversationQuota int64 = 100 << 20 // 104857600
	defaultFileStoreMaxBytes     int64 = 2 << 30   // 2147483648
	defaultFileAccountDaily      int64 = 100 << 20 // 104857600

	decimalBase = 10
	int64Bits   = 64
)

// getEnvInt64Default reads a positive int64 setting as getEnvIntDefault reads an int: missing or
// empty is the default, anything that is not a positive integer reads as 0 (fails its bound).
func getEnvInt64Default(key string, defaultValue int64) int64 {
	value := strings.TrimSpace(GetEnv(key, ""))
	if value == "" {
		return defaultValue
	}
	parsed, err := strconv.ParseInt(value, decimalBase, int64Bits)
	if err != nil || parsed <= 0 {
		return 0
	}
	return parsed
}

// GetMaxFileBytes returns the largest file one message may announce (its plaintext size)
func GetMaxFileBytes() int64 {
	return getEnvInt64Default(EnvMaxFileBytes, defaultMaxFileBytes)
}

// GetFileConversationQuotaBytes returns how many bytes of stored parts one conversation may hold
func GetFileConversationQuotaBytes() int64 {
	return getEnvInt64Default(EnvFileConversationQuotaBytes, defaultFileConversationQuota)
}

// GetFileStoreMaxBytes returns how many bytes of stored parts the whole server may hold
func GetFileStoreMaxBytes() int64 {
	return getEnvInt64Default(EnvFileStoreMaxBytes, defaultFileStoreMaxBytes)
}

// GetFileAccountDailyBytes returns how many bytes of parts one account may store per day (an
// in-memory budget that refills over a day)
func GetFileAccountDailyBytes() int64 {
	return getEnvInt64Default(EnvFileAccountDailyBytes, defaultFileAccountDaily)
}

// ========================================
// SECURITY CONFIGURATION
// ========================================

// GetAllowedOrigins returns CORS allowed origins (comma-separated)
func GetAllowedOrigins() string {
	return GetEnv(EnvAllowedOrigins, defaultAllowedOrigins)
}

// GetAppEnv returns the deployment environment, lower-cased (startup validation lists the
// accepted values)
func GetAppEnv() string {
	return strings.ToLower(strings.TrimSpace(GetEnv(EnvAppEnv, defaultAppEnv)))
}

// IsProductionMode returns true if running in production
func IsProductionMode() bool {
	env := GetAppEnv()
	return env == "production" || env == "prod"
}

// GetLogLevel returns logging level
// Values: debug, info, warn, error
func GetLogLevel() string {
	return strings.ToLower(strings.TrimSpace(GetEnv(EnvLogLevel, defaultLogLevel)))
}

// GetTrustedProxies returns comma-separated trusted proxy IPs/CIDRs
func GetTrustedProxies() string {
	return strings.TrimSpace(GetEnv(EnvTrustedProxies, ""))
}

// ========================================
// RATE LIMITING
// ========================================

// GetRateLimitMaxTokens returns max tokens per bucket
func GetRateLimitMaxTokens() int {
	return getEnvIntDefault(EnvRateLimitMaxTokens, defaultRateLimitMaxTokens)
}

// GetRateLimitRefillIntervalSeconds returns refill interval in seconds
func GetRateLimitRefillIntervalSeconds() int {
	return getEnvIntDefault(EnvRateLimitRefillIntervalSeconds, defaultRateLimitRefillSeconds)
}

// GetRateLimitCleanupIntervalSeconds returns cleanup interval in seconds
func GetRateLimitCleanupIntervalSeconds() int {
	return getEnvIntDefault(EnvRateLimitCleanupIntervalSeconds, defaultRateLimitCleanupSeconds)
}

// GetRateLimitMaxBuckets returns max bucket count before cleanup
func GetRateLimitMaxBuckets() int {
	return getEnvIntDefault(EnvRateLimitMaxBuckets, defaultRateLimitMaxBuckets)
}

// ========================================
// DATABASE CONFIGURATION
// ========================================

// GetDBHost returns database host
func GetDBHost() string {
	return strings.TrimSpace(GetEnv(EnvDBHost, defaultDBHost))
}

// GetDBPort returns database port
func GetDBPort() string {
	return strings.TrimSpace(GetEnv(EnvDBPort, defaultDBPort))
}

// GetDBUser returns database user
func GetDBUser() string {
	return strings.TrimSpace(GetEnv(EnvDBUser, defaultDBUser))
}

// GetDBPassword returns the database password; there is no default (make setup generates one)
func GetDBPassword() string {
	return GetEnv(EnvDBPassword, "")
}

// GetDBName returns database name
func GetDBName() string {
	return strings.TrimSpace(GetEnv(EnvDBName, defaultDBName))
}

// GetDBSSLMode returns database SSL mode
// Values: disable, require, verify-ca, verify-full
func GetDBSSLMode() string {
	// Note: Logging is handled in database.connection.go ValidateStartupConfig
	return strings.TrimSpace(GetEnv(EnvDBSSLMode, defaultDBSSLMode))
}

// ========================================
// ENCRYPTION CONFIGURATION
// ========================================

// GetArgon2MemoryKiB returns Argon2 memory in KiB
func GetArgon2MemoryKiB() int {
	return getEnvIntDefault(EnvArgon2MemoryKiB, defaultArgon2MemoryKiB)
}

// GetArgon2Time returns Argon2 time cost
func GetArgon2Time() int {
	return getEnvIntDefault(EnvArgon2Time, defaultArgon2Time)
}

// GetArgon2Parallelism returns Argon2 parallelism
func GetArgon2Parallelism() int {
	return getEnvIntDefault(EnvArgon2Parallelism, defaultArgon2Parallelism)
}

// GetArgon2MaxConcurrent returns how many Argon2id computations may run at once
func GetArgon2MaxConcurrent() int {
	return getEnvIntDefault(EnvArgon2MaxConcurrent, defaultArgon2MaxConcurrent)
}

// GetArgon2SaltLength returns Argon2 salt length in bytes
func GetArgon2SaltLength() int {
	return getEnvIntDefault(EnvArgon2SaltLength, defaultArgon2SaltLength)
}

// GetArgon2HashLength returns Argon2 hash length in bytes
func GetArgon2HashLength() int {
	return getEnvIntDefault(EnvArgon2HashLength, defaultArgon2HashLength)
}

// MinPepperBytes returns the shortest account-lookup pepper accepted, in bytes.
func MinPepperBytes() int {
	return minPepperBytes
}

// GetAccountLookupPepper returns the pepper for account lookup HMAC: at least 32 bytes of
// key material encoded as hex or base64. Raw text is rejected (nil), never used as bytes.
func GetAccountLookupPepper() []byte {
	pepperStr := strings.TrimSpace(GetEnv(EnvAccountLookupPepper, ""))
	if pepperStr == "" {
		return nil
	}
	if decoded, err := hex.DecodeString(pepperStr); err == nil && len(decoded) >= minPepperBytes {
		return decoded
	}
	if decoded, err := base64.StdEncoding.Strict().DecodeString(pepperStr); err == nil && len(decoded) >= minPepperBytes {
		return decoded
	}
	return nil
}

// ========================================
// PENDING REGISTRATION CONFIGURATION
// ========================================

// GetPendingTokenTTL returns pending token TTL
func GetPendingTokenTTL() time.Duration {
	return getEnvSecondsDefault(EnvPendingTokenTTLSeconds, defaultPendingTokenTTLSeconds, MaxPendingTokenTTLSeconds)
}

// GetPendingCleanupInterval returns pending store cleanup interval
func GetPendingCleanupInterval() time.Duration {
	return getEnvSecondsDefault(EnvPendingCleanupIntervalSeconds, defaultPendingCleanupSeconds, MaxPendingCleanupSeconds)
}

// GetPendingIDBytes returns pending ID length in bytes
func GetPendingIDBytes() int {
	return getEnvIntDefault(EnvPendingIDBytes, defaultPendingIDBytes)
}

// ========================================
// IDENTIFIER CONFIGURATION
// ========================================

// GetInternalIDLength returns internal UUID length
func GetInternalIDLength() int {
	return getEnvIntDefault(EnvInternalIDLength, defaultInternalIDLength)
}

// ========================================
// SERVER CONFIGURATION
// ========================================

// GetBackendPort returns backend server port
func GetBackendPort() string {
	return strings.TrimSpace(GetEnv(EnvBackendPort, defaultBackendPort))
}

// GetServerReadHeaderTimeout returns read header timeout
func GetServerReadHeaderTimeout() time.Duration {
	return getEnvSecondsDefault(EnvServerReadHeaderTimeoutSeconds, defaultServerReadHeaderTimeout, MaxServerReadHeaderTimeoutSeconds)
}

// GetServerReadTimeout returns read timeout
func GetServerReadTimeout() time.Duration {
	return getEnvSecondsDefault(EnvServerReadTimeoutSeconds, defaultServerReadTimeout, MaxServerReadTimeoutSeconds)
}

// GetServerWriteTimeout returns write timeout
func GetServerWriteTimeout() time.Duration {
	return getEnvSecondsDefault(EnvServerWriteTimeoutSeconds, defaultServerWriteTimeout, MaxServerWriteTimeoutSeconds)
}

// GetServerIdleTimeout returns idle timeout
func GetServerIdleTimeout() time.Duration {
	return getEnvSecondsDefault(EnvServerIdleTimeoutSeconds, defaultServerIdleTimeout, MaxServerIdleTimeoutSeconds)
}

// GetServerMaxHeaderBytes returns max header bytes
func GetServerMaxHeaderBytes() int {
	return getEnvIntDefault(EnvServerMaxHeaderBytes, defaultServerMaxHeaderBytes)
}

// ========================================
// PROOF OF WORK CONFIGURATION
// ========================================

// GetPoWDifficulty returns the PoW difficulty level
func GetPoWDifficulty() int {
	return getEnvIntDefault(EnvPoWDifficulty, defaultPoWDifficulty)
}

// GetPoWChallengeTTL returns how long an issued PoW challenge stays valid
func GetPoWChallengeTTL() time.Duration {
	return getEnvSecondsDefault(EnvPoWChallengeTTLSeconds, defaultPoWChallengeTTLSeconds, MaxPoWChallengeTTLSeconds)
}

// DefaultPoWDifficulty returns the default PoW difficulty level
func DefaultPoWDifficulty() int {
	return defaultPoWDifficulty
}

// MinPoWDifficulty returns the minimum PoW difficulty level
func MinPoWDifficulty() int {
	return minPoWDifficulty
}

// MaxPoWDifficulty returns the maximum PoW difficulty level
func MaxPoWDifficulty() int {
	return maxPoWDifficulty
}
