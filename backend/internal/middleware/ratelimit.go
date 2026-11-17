package middleware

import (
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
	"elyrn/internal/utils"
)

var rateLimitLogger = utils.NewLogger("RATE_LIMIT")

// TokenBucket implements a simple token bucket rate limiter
type TokenBucket struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	lastAccess time.Time // Track last access time for cleanup
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket
func NewTokenBucket(maxTokens int, refillRate time.Duration) *TokenBucket {
	now := time.Now()
	return &TokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: now,
		lastAccess: now,
	}
}

// Allow checks if a request is allowed (consumes one token)
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	tb.lastAccess = now // Update last access time
	elapsed := now.Sub(tb.lastRefill)

	// Refill tokens based on elapsed time
	if elapsed > 0 {
		tokensToAdd := int(elapsed / tb.refillRate)
		if tokensToAdd > 0 {
			tb.tokens = tb.tokens + tokensToAdd
			if tb.tokens > tb.maxTokens {
				tb.tokens = tb.maxTokens
			}
			tb.lastRefill = now
		}
	}

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

// full reports whether the bucket holds, or by now would hold after refilling, all its tokens:
// dropping it then hands nothing back that a new bucket would not have.
func (tb *TokenBucket) full(now time.Time) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	missing := tb.maxTokens - tb.tokens
	return missing <= 0 || now.Sub(tb.lastRefill) >= time.Duration(missing)*tb.refillRate
}

// Refund gives back one token that Allow took for work that was then not done, never above the
// bucket's size.
func (tb *TokenBucket) Refund() {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.tokens < tb.maxTokens {
		tb.tokens++
	}
}

// limiterSettings is what one limiter's buckets are made of, read from the configuration at
// every use (so tests and a changed environment take effect for buckets created afterwards).
type limiterSettings struct {
	maxTokens       int
	refillInterval  time.Duration
	cleanupInterval time.Duration
	maxBuckets      int
	// idleLimit: a bucket untouched this long is dropped (keepSpent false)
	idleLimit time.Duration
	// keepSpent: a bucket is dropped only once it would be full again, never earlier (dropping
	// it would hand its tokens back), and a limiter full of such buckets refuses a new key
	// instead of evicting one (fail closed)
	keepSpent bool
}

// RateLimiter stores token buckets per client key (Lock order: rl.mu before bucket.mu)
type RateLimiter struct {
	buckets         map[string]*TokenBucket
	mu              sync.RWMutex
	settings        func() (limiterSettings, error)
	cleanupInterval time.Duration
	lastCleanup     time.Time
	maxTokens       int
	refillInterval  time.Duration
	maxBuckets      int
	idleLimit       time.Duration
	keepSpent       bool
}

var globalRateLimiter = &RateLimiter{
	buckets:  make(map[string]*TokenBucket),
	settings: globalSettings,
}

var errLimiterConfig = errors.New("rate limit config not set")

// globalSettings are the RATE_LIMIT_* settings of the shared limiter.
func globalSettings() (limiterSettings, error) {
	maxTokens := config.GetRateLimitMaxTokens()
	refillSec := config.GetRateLimitRefillIntervalSeconds()
	cleanupSec := config.GetRateLimitCleanupIntervalSeconds()
	maxBuckets := config.GetRateLimitMaxBuckets()
	if maxTokens <= 0 || refillSec <= 0 || cleanupSec <= 0 || maxBuckets <= 0 {
		return limiterSettings{}, errLimiterConfig
	}
	return limiterSettings{maxTokens: maxTokens, refillInterval: time.Duration(refillSec) * time.Second,
		cleanupInterval: time.Duration(cleanupSec) * time.Second, maxBuckets: maxBuckets, idleLimit: inactivityThreshold}, nil
}

func (rl *RateLimiter) loadConfig() error {
	s, err := rl.settings()
	if err != nil {
		return err
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	rl.maxTokens = s.maxTokens
	rl.refillInterval = s.refillInterval
	rl.cleanupInterval = s.cleanupInterval
	rl.maxBuckets = s.maxBuckets
	rl.idleLimit = s.idleLimit
	rl.keepSpent = s.keepSpent
	if rl.lastCleanup.IsZero() {
		rl.lastCleanup = time.Now()
	}
	return nil
}

// inactivityThreshold drops the shared limiter's buckets nobody has touched for an hour
const inactivityThreshold = time.Hour

// getBucket returns the bucket for key, creating it if needed. The bucket count is bounded
// at insertion: when the limiter is full, the least recently used tenth is evicted in one
// O(n log n) pass, so a flood of new keys costs amortised O(log n) and bounded memory. A
// keepSpent limiter evicts no bucket that is not full again: full of those, it answers nil.
func (rl *RateLimiter) getBucket(key string) *TokenBucket {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	if now.Sub(rl.lastCleanup) > rl.cleanupInterval {
		rl.evictInactiveLocked(now)
		rl.lastCleanup = now
	}
	if bucket, ok := rl.buckets[key]; ok {
		return bucket
	}
	if len(rl.buckets) >= rl.maxBuckets {
		rl.evictInactiveLocked(now)
	}
	if len(rl.buckets) >= rl.maxBuckets {
		if rl.keepSpent {
			return nil
		}
		rl.evictOldestLocked(len(rl.buckets) - rl.maxBuckets + 1 + rl.maxBuckets/10)
	}
	bucket := NewTokenBucket(rl.maxTokens, rl.refillInterval)
	rl.buckets[key] = bucket
	return bucket
}

func (rl *RateLimiter) lastAccess(bucket *TokenBucket) time.Time {
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.lastAccess
}

// evictInactiveLocked removes the buckets that can go without changing an answer: idle past
// the idle limit, or, for a keepSpent limiter, full again. Caller holds rl.mu.
func (rl *RateLimiter) evictInactiveLocked(now time.Time) {
	for key, bucket := range rl.buckets {
		if rl.keepSpent && bucket.full(now) || !rl.keepSpent && now.Sub(rl.lastAccess(bucket)) > rl.idleLimit {
			delete(rl.buckets, key)
		}
	}
}

// evictOldestLocked removes the n least recently used buckets. Caller holds rl.mu.
func (rl *RateLimiter) evictOldestLocked(n int) {
	type entry struct {
		key        string
		lastAccess time.Time
	}
	entries := make([]entry, 0, len(rl.buckets))
	for key, bucket := range rl.buckets {
		entries = append(entries, entry{key: key, lastAccess: rl.lastAccess(bucket)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].lastAccess.Before(entries[j].lastAccess) })
	for i := 0; i < n && i < len(entries); i++ {
		delete(rl.buckets, entries[i].key)
	}
	rateLimitLogger.Debug("RateLimiter: limiter full, evicted %d least recently used buckets", n)
}

// RateLimitMiddleware limits requests per IP for login and register endpoints
func RateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := globalRateLimiter.loadConfig(); err != nil {
			apperr.WriteError(w, "RateLimitMiddleware: config", err)
			return
		}

		client, err := ClientKey(r)
		if err != nil {
			apperr.WriteError(w, "RateLimitMiddleware: ClientKey", err)
			return
		}
		bucket := globalRateLimiter.getBucket("ip:" + client)

		if !bucket.Allow() {
			apperr.Write(w, "RateLimitMiddleware", apperr.RateLimited)
			return
		}

		next(w, r)
	}
}
