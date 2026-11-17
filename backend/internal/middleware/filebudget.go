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
// buckets (RATE_LIMIT_MAX_BUCKETS), but a budget is dropped only once it would be full again:
// eviction never hands an account a fresh budget. With every budget still spent, a new one is
// refused (the upload answers E_FILE_BUDGET_SPENT) instead of evicting one. A budget is created
// only for an authenticated account: FileBudget is called by the upload handler after the
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

// FileBudget is the upload budget of the account behind streamTag: take one part with Allow,
// give it back with Refund when the part was not stored. It is nil when the settings are
// unusable (startup validation refuses them first) or every budget held is still spent and the
// bound is reached: the caller then refuses the upload (fail closed).
func FileBudget(streamTag string) *TokenBucket {
	if err := fileBudgets.loadConfig(); err != nil {
		rateLimitLogger.LogError("FileBudgetConfig", err)
		return nil
	}
	if streamTag == "" {
		return nil
	}
	return fileBudgets.getBucket(streamTag)
}
