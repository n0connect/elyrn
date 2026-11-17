//go:build test
// +build test

package middleware

import "time"

// ResetRateLimiterForTesting clears all buckets for testing purposes
// SECURITY: This function is ONLY available in test builds (build tag: test)
// It will NOT be compiled into production binaries, preventing security risks
func ResetRateLimiterForTesting() {
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

// RateLimiterBucketCountForTesting reports how many buckets the global limiter holds.
func RateLimiterBucketCountForTesting() int {
	globalRateLimiter.mu.RLock()
	defer globalRateLimiter.mu.RUnlock()
	return len(globalRateLimiter.buckets)
}
