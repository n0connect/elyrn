//go:build test
// +build test

package middleware

import "time"

// ResetRateLimiterForTesting clears all buckets for testing purposes
// SECURITY: This function is ONLY available in test builds (build tag: test)
// It will NOT be compiled into production binaries, preventing security risks
func ResetRateLimiterForTesting() {
	// Test builds only. Every live path (RateLimitMiddleware, AllowKey) loads the settings again
	// and fails closed on an error, so a bad setting still surfaces at the test's next request
	_ = globalRateLimiter.loadConfig()
	globalRateLimiter.mu.Lock()
	defer globalRateLimiter.mu.Unlock()
	globalRateLimiter.buckets = make(map[string]*TokenBucket)
	globalRateLimiter.lastCleanup = time.Now()
	rateLimitLogger.Debug("RateLimiter: reset for testing")
}

// ResetFileBudgetsForTesting drops every file budget, as a restart does.
func ResetFileBudgetsForTesting() {
	fileBudgets.mu.Lock()
	defer fileBudgets.mu.Unlock()
	fileBudgets.buckets = make(map[string]*TokenBucket)
}

// FileBudgetCountForTesting reports how many file budgets are held.
func FileBudgetCountForTesting() int {
	fileBudgets.mu.RLock()
	defer fileBudgets.mu.RUnlock()
	return len(fileBudgets.buckets)
}

// FileBudgetDeficitForTesting reports how many parts the budget of streamTag lacks now (refill
// included) and whether that budget is held at all.
func FileBudgetDeficitForTesting(streamTag string) (int, bool) {
	fileBudgets.mu.RLock()
	defer fileBudgets.mu.RUnlock()
	bucket, ok := fileBudgets.buckets[streamTag]
	if !ok {
		return 0, false
	}
	return bucket.deficit(time.Now()), true
}

// RateLimiterBucketCountForTesting reports how many buckets the global limiter holds.
func RateLimiterBucketCountForTesting() int {
	globalRateLimiter.mu.RLock()
	defer globalRateLimiter.mu.RUnlock()
	return len(globalRateLimiter.buckets)
}
