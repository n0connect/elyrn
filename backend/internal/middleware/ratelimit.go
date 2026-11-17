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
	return tb.allowLocked(time.Now())
}

// allowLocked takes one token at now, after refilling. Caller holds tb.mu.
func (tb *TokenBucket) allowLocked(now time.Time) bool {
	tb.lastAccess = now
	tb.refillLocked(now)
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}
	return false
}

// refillLocked adds one token per whole refillRate since the last one was added, and keeps the
// part of an interval that has not completed yet, so the bucket refills exactly at its configured
// rate, never faster: time while the bucket is full earns nothing (the clock restarts once a token
// is taken from a full bucket). Caller holds tb.mu.
func (tb *TokenBucket) refillLocked(now time.Time) {
	if tb.tokens >= tb.maxTokens {
		tb.lastRefill = now
		return
	}
	elapsed := now.Sub(tb.lastRefill)
	if elapsed < tb.refillRate {
		return
	}
	added := min(elapsed/tb.refillRate, time.Duration(tb.maxTokens-tb.tokens))
	tb.tokens += int(added)
	if tb.tokens >= tb.maxTokens {
		tb.lastRefill = now
		return
	}
	tb.lastRefill = tb.lastRefill.Add(added * tb.refillRate)
}

// deficit is how many tokens the bucket lacks at now, refill included: what dropping it and
// creating a fresh one would hand back (0: it is full again).
func (tb *TokenBucket) deficit(now time.Time) int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	tb.refillLocked(now)
	return tb.maxTokens - tb.tokens
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
	// keepSpent: a bucket is dropped at cleanup only once it is full again (dropping it earlier
	// would hand its tokens back), and a full limiter evicts the one bucket closest to full, so
	// an evicted key regains at most that bucket's deficit, the smallest held, and no key is
	// ever refused because of the others
	keepSpent bool
}

// RateLimiter stores token buckets per client key. Every use of a bucket (take, refund) happens
// while rl.mu is held, so no caller ever spends from a bucket that was evicted meanwhile (Lock
// order: rl.mu before bucket.mu).
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

// take spends one token of key's bucket (created full if absent) and reports whether there was
// one. Lookup and spending happen under one hold of rl.mu.
func (rl *RateLimiter) take(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return rl.bucketLocked(key).Allow()
}

// refund gives back a token key's bucket gave for work that was not done; a key no longer held
// (its bucket was full again and dropped, or evicted as the fullest) needs none.
func (rl *RateLimiter) refund(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if bucket, ok := rl.buckets[key]; ok {
		bucket.Refund()
	}
}

// bucketLocked returns the bucket for key, creating it if needed. The bucket count is bounded
// at insertion: when the limiter is full, the least recently used tenth is evicted in one
// O(n log n) pass (a keepSpent limiter: the one bucket closest to full, O(n)), so a flood of new
// keys costs amortised O(log n) and bounded memory. Caller holds rl.mu.
func (rl *RateLimiter) bucketLocked(key string) *TokenBucket {
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
			rl.evictFullestLocked(now)
		} else {
			rl.evictOldestLocked(len(rl.buckets) - rl.maxBuckets + 1 + rl.maxBuckets/10)
		}
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
		if rl.keepSpent && bucket.deficit(now) == 0 || !rl.keepSpent && now.Sub(rl.lastAccess(bucket)) > rl.idleLimit {
			delete(rl.buckets, key)
		}
	}
}

// evictFullestLocked removes the one bucket with the smallest deficit at now (ties: the least
// recently used): its key regains at most that deficit, the smallest any key could. Caller
// holds rl.mu.
func (rl *RateLimiter) evictFullestLocked(now time.Time) {
	var victim string
	var victimDeficit int
	var victimAccess time.Time
	found := false
	for key, bucket := range rl.buckets {
		d, access := bucket.deficit(now), rl.lastAccess(bucket)
		if !found || d < victimDeficit || d == victimDeficit && access.Before(victimAccess) {
			victim, victimDeficit, victimAccess, found = key, d, access, true
		}
	}
	if found {
		delete(rl.buckets, victim)
		rateLimitLogger.Debug("RateLimiter: limiter full, evicted the bucket closest to full")
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
		if !globalRateLimiter.take("ip:" + client) {
			apperr.Write(w, "RateLimitMiddleware", apperr.RateLimited)
			return
		}

		next(w, r)
	}
}
