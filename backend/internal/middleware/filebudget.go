package middleware

import (
	"time"

	"elyrn/internal/config"
	"elyrn/internal/utils"
)

// fileBudgetWindow: an account's file budget refills from empty to full over one day
const fileBudgetWindow = 24 * time.Hour

// fileBudgets holds each account's upload budget: FILE_ACCOUNT_DAILY_BYTES worth of stored file
// parts, refilled continuously over fileBudgetWindow. It lives in memory only, keyed by the
// account's in-memory stream tag like the rate buckets, so nothing about an account's upload
// volume reaches the database (where per-conversation pseudonyms must stay unjoinable); it
// resets when the process restarts. The number of budgets is bounded like the shared limiter's
// buckets (RATE_LIMIT_MAX_BUCKETS): a budget is dropped at cleanup only once it is full again,
// and a full map evicts the budget closest to full, so an evicted account regains at most that
// budget's deficit (the smallest held) and nobody is refused because of other accounts. A
// budget is created only for an authenticated account: the upload handler takes one after the
// session gate (JWTMiddleware) and resolveMe, with that account's stream tag.
var fileBudgets = &RateLimiter{
	buckets:  make(map[string]*TokenBucket),
	settings: fileBudgetSettings,
}

// fileBudgetSettings: one token per part, refilled at the rate that fills the budget in a day.
func fileBudgetSettings() (limiterSettings, error) {
	parts := config.GetFileAccountDailyBytes() / utils.FilePartBytes
	cleanupSec := config.GetRateLimitCleanupIntervalSeconds()
	maxBuckets := config.GetRateLimitMaxBuckets()
	if parts <= 0 || cleanupSec <= 0 || maxBuckets <= 0 {
		return limiterSettings{}, errLimiterConfig
	}
	return limiterSettings{maxTokens: int(parts), refillInterval: fileBudgetWindow / time.Duration(parts),
		cleanupInterval: time.Duration(cleanupSec) * time.Second, maxBuckets: maxBuckets, keepSpent: true}, nil
}

// FileBudget is the upload budget of one account, named by its stream tag. It holds no bucket:
// taking and giving back a part are operations of the budget map by key, under its lock, so an
// eviction between the two never leaves a caller spending from a detached budget.
type FileBudget struct {
	key string
}

// FileBudgetOf is the budget of the account behind streamTag.
func FileBudgetOf(streamTag string) FileBudget {
	return FileBudget{key: streamTag}
}

// Allow takes one part from the budget; false when it is spent, when the account has no stream
// tag, or when the settings are unusable (startup validation refuses those first): fail closed.
func (b FileBudget) Allow() bool {
	if err := fileBudgets.loadConfig(); err != nil {
		rateLimitLogger.LogError("FileBudgetConfig", err)
		return false
	}
	return b.key != "" && fileBudgets.take(b.key)
}

// Refund gives back a part Allow took for a part that was not stored.
func (b FileBudget) Refund() {
	fileBudgets.refund(b.key)
}
