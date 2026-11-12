package pow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

const (
	// ChallengeBytes and SaltBytes are the issued sizes; challenges travel as lowercase hex.
	// The salt carries the challenge's MAC (mac.go), so it keeps its issued width.
	ChallengeBytes = 16
	SaltBytes      = 16
	// Worker emits a decimal nonce below 10^7; 20 digits bounds any uint64.
	maxSolutionDigits = 20
	// Challenge rate limit per client: phase 1 + phase 2 of one registration plus retries
	challengesPerWindow = 5
	challengeWindow     = time.Minute
	// limiterIdleTimeout: a limiter idle for one window has refilled, so evicting it then loses
	// nothing, and the client cap below takes a minute's worth of clients to fill, not an hour's
	limiterIdleTimeout = challengeWindow
	cleanupInterval    = time.Minute
	// maxCleanupCycles bounds the cleanup loop (RULES.md §8.1); one per minute outlives any deployment
	maxCleanupCycles = 1 << 26
	// maxSpentChallenges bounds solved, unexpired challenges kept for single use (~150 bytes
	// each). Every entry cost its sender a full proof of work. maxTrackedClients bounds
	// per-client limiters. Past either cap the server fails closed (ErrCapacity, 503).
	maxSpentChallenges = 50000
	maxTrackedClients  = 50000
)

var (
	// ErrRateLimited: this client asked for too many challenges in the current window
	ErrRateLimited = errors.New("pow: rate limit exceeded")
	// ErrCapacity: the issuer or the spent set is at its memory bound (flood in progress); retry later
	ErrCapacity = errors.New("pow: challenge capacity reached")
	// ErrInvalidSolution: malformed, forged, expired, replayed, or below the issued difficulty
	ErrInvalidSolution = errors.New("pow: invalid solution")
)

type RateLimiter struct {
	tokens         int
	maxTokens      int
	refillTime     time.Time
	refillInterval time.Duration
	lastAccess     time.Time // For cleanup tracking
	mutex          sync.Mutex
}

func NewRateLimiter(maxTokens int, refillInterval time.Duration) *RateLimiter {
	now := time.Now()
	return &RateLimiter{
		tokens:         maxTokens,
		maxTokens:      maxTokens,
		refillTime:     now.Add(refillInterval),
		refillInterval: refillInterval,
		lastAccess:     now,
	}
}

func (rl *RateLimiter) Allow() bool {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	rl.lastAccess = now

	// Refill tokens if necessary
	if now.After(rl.refillTime) {
		rl.tokens = rl.maxTokens
		rl.refillTime = now.Add(rl.refillInterval)
	}

	if rl.tokens <= 0 {
		return false
	}

	rl.tokens--
	return true
}

var (
	powLogger = utils.NewLogger("POW")
	// spentChallenges maps a solved challenge to the Unix second it expires; only solved
	// challenges are kept (issuing stores nothing). spentMutex guards it and is a leaf lock:
	// nothing else is acquired while it is held.
	spentChallenges = make(map[string]int64)
	spentMutex      sync.Mutex
	// Rate limiter for challenge requests per client key
	challengeRateLimiters = make(map[string]*RateLimiter)
	rateLimiterMutex      = sync.RWMutex{}
)

// GenerateChallenge issues a proof of work challenge without storing it: the salt
// authenticates every field the client echoes back (mac.go). clientKey is an opaque
// per-client pseudonym used only for rate limiting.
func GenerateChallenge(clientKey string) (*models.PoWChallenge, error) {
	if err := admitClient(clientKey); err != nil {
		return nil, err
	}
	difficulty := getAdaptiveDifficulty()
	ttl := int64(config.GetPoWChallengeTTL() / time.Second)
	challenge, err := newChallenge(time.Now(), ttl, difficulty)
	if err != nil {
		return nil, err
	}
	powLogger.Debug("Generated PoW challenge with difficulty: %d", difficulty)
	return challenge, nil
}

// admitClient charges one challenge to clientKey's limiter, creating it within the
// tracked-client bound.
func admitClient(clientKey string) error {
	rateLimiterMutex.Lock()
	limiter, exists := challengeRateLimiters[clientKey]
	if !exists {
		if len(challengeRateLimiters) >= maxTrackedClients {
			rateLimiterMutex.Unlock()
			cleanupInactiveRateLimiters(time.Now())
			rateLimiterMutex.Lock()
		}
		if len(challengeRateLimiters) >= maxTrackedClients {
			rateLimiterMutex.Unlock()
			powLogger.Warn("Challenge issuer at client capacity")
			return ErrCapacity
		}
		limiter = NewRateLimiter(challengesPerWindow, challengeWindow)
		challengeRateLimiters[clientKey] = limiter
	}
	rateLimiterMutex.Unlock()

	if !limiter.Allow() {
		powLogger.Warn("Challenge rate limit exceeded")
		return ErrRateLimited
	}
	return nil
}

// newChallenge draws a fresh challenge issued at now and seals its fields into the salt.
func newChallenge(now time.Time, ttl int64, difficulty int) (*models.PoWChallenge, error) {
	key, err := challengeSecret()
	if err != nil {
		powLogger.LogError("challengeSecret", err)
		return nil, err
	}
	challengeBytes, err := cryptoengine.RandomBytes(ChallengeBytes)
	if err != nil {
		powLogger.LogError("RandomBytes", err)
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	challenge := &models.PoWChallenge{
		Challenge:  hex.EncodeToString(challengeBytes),
		Timestamp:  now.Unix(),
		Difficulty: difficulty,
		TTL:        ttl,
	}
	challenge.Salt, err = challengeTag(key, challenge.Challenge, challenge.Timestamp, ttl, difficulty)
	if err != nil {
		powLogger.LogError("challengeTag", err)
		return nil, err
	}
	return challenge, nil
}

// RunCleanup evicts expired spent challenges and idle per-client limiters every minute until
// ctx ends. Run it under utils.SafeGoSupervised.
func RunCleanup(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for cycle := 0; cycle < maxCleanupCycles; cycle++ {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			cleanupSpentChallenges(now)
			cleanupInactiveRateLimiters(now)
		}
	}
}

// cleanupSpentChallenges forgets spent challenges that expired before now
func cleanupSpentChallenges(now time.Time) {
	spentMutex.Lock()
	defer spentMutex.Unlock()
	removeExpiredSpentLocked(now)
}

// removeExpiredSpentLocked deletes spent challenges past their expiry. A forgotten challenge
// stays refused: validation rejects it as expired before the spent set is consulted. Caller
// holds spentMutex.
func removeExpiredSpentLocked(now time.Time) {
	cleaned := 0
	for key, expiresAt := range spentChallenges {
		if expired(expiresAt, now) {
			delete(spentChallenges, key)
			cleaned++
		}
	}
	if cleaned > 0 {
		powLogger.Debug("Cleaned %d expired spent challenges, remaining: %d", cleaned, len(spentChallenges))
	}
}

// expired reports whether a challenge expiring at the Unix second expiresAt is past it at now;
// validation and eviction share it so nothing is evicted that validation would still accept.
func expired(expiresAt int64, now time.Time) bool {
	return now.After(time.Unix(expiresAt, 0))
}

// cleanupInactiveRateLimiters removes limiters idle for longer than limiterIdleTimeout at now
func cleanupInactiveRateLimiters(now time.Time) {
	rateLimiterMutex.Lock()
	defer rateLimiterMutex.Unlock()

	cleaned := 0
	for key, limiter := range challengeRateLimiters {
		limiter.mutex.Lock()
		if now.Sub(limiter.lastAccess) > limiterIdleTimeout {
			delete(challengeRateLimiters, key)
			cleaned++
		}
		limiter.mutex.Unlock()
	}
	if cleaned > 0 {
		powLogger.Debug("Cleaned %d inactive rate limiters, remaining: %d", cleaned, len(challengeRateLimiters))
	}
}

// ValidateSolution admits a solution to a challenge this server issued (its salt verifies),
// unexpired, never solved before, whose hash meets the issued difficulty, and marks it spent.
// It returns nil, ErrInvalidSolution, ErrCapacity (spent set full), or a wrapped internal
// failure (no secret, hash failure) that the caller answers 500.
func ValidateSolution(solution *models.PoWSolution) error {
	expiresAt, err := checkSolution(solution, time.Now())
	if err != nil {
		return err
	}
	return spend(solution.Challenge, expiresAt)
}

// checkSolution verifies everything that needs no shared state and returns the expiry.
func checkSolution(solution *models.PoWSolution, now time.Time) (int64, error) {
	if solution == nil {
		powLogger.Warn("Nil PoW solution provided")
		return 0, ErrInvalidSolution
	}
	// Whitelist the shape of every client-supplied field before any computation
	if !IsHexOfLen(solution.Challenge, ChallengeBytes) || !IsHexOfLen(solution.Salt, SaltBytes) ||
		!isDecimal(solution.Solution, maxSolutionDigits) || solution.TTL <= 0 {
		powLogger.Warn("Malformed PoW solution rejected")
		return 0, ErrInvalidSolution
	}
	ok, err := tagMatches(solution.Challenge, solution.Salt, solution.Timestamp, solution.TTL, solution.Difficulty)
	if err != nil {
		powLogger.LogError("tagMatches", err)
		return 0, err
	}
	if !ok {
		powLogger.Warn("PoW challenge not issued by this server (or issued before a restart)")
		return 0, ErrInvalidSolution
	}
	// Timestamp, ttl and difficulty are authenticated from here on: they are the issued values
	expiresAt := solution.Timestamp + solution.TTL
	if expired(expiresAt, now) {
		powLogger.Warn("PoW solution expired")
		return 0, ErrInvalidSolution
	}
	// Verify the proof of work: SHA-256(challenge || nonce || salt) under the issued difficulty
	hash, err := cryptoengine.SHA256([]byte(solution.Challenge + solution.Solution + solution.Salt))
	if err != nil {
		powLogger.LogError("SHA256", err)
		return 0, fmt.Errorf("pow hash: %w", err)
	}
	if !HasLeadingZeroBits(hash, solution.Difficulty) {
		powLogger.Warn("PoW solution below the issued difficulty")
		return 0, ErrInvalidSolution
	}
	return expiresAt, nil
}

// spend records a verified challenge as used, atomically refusing a second use. A failed
// attempt never reaches here, so it does not burn the challenge.
func spend(challenge string, expiresAt int64) error {
	spentMutex.Lock()
	defer spentMutex.Unlock()
	if _, used := spentChallenges[challenge]; used {
		powLogger.Warn("PoW challenge already used (replay attack)")
		return ErrInvalidSolution
	}
	if len(spentChallenges) >= maxSpentChallenges {
		removeExpiredSpentLocked(time.Now())
	}
	if len(spentChallenges) >= maxSpentChallenges {
		powLogger.Warn("Spent challenge set at capacity")
		return ErrCapacity
	}
	spentChallenges[challenge] = expiresAt
	powLogger.Debug("Valid PoW solution accepted")
	return nil
}

// IsHexOfLen reports whether s is exactly byteLen bytes of lowercase hex, as issued.
func IsHexOfLen(s string, byteLen int) bool {
	if len(s) != byteLen*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func isDecimal(s string, maxDigits int) bool {
	if len(s) == 0 || len(s) > maxDigits {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// HasLeadingZeroBits checks if the hash has at least n leading zero bits (the verifier's
// rule; clients that solve challenges in Go use the same function)
func HasLeadingZeroBits(hash []byte, n int) bool {
	if n <= 0 {
		return true
	}

	zeroBits := 0

	for _, b := range hash {
		if b == 0 {
			zeroBits += 8
		} else {
			// Count leading zeros in this byte
			for bit := 7; bit >= 0; bit-- {
				if (b>>bit)&1 == 0 {
					zeroBits++
				} else {
					break
				}
			}
			break
		}

		if zeroBits >= n {
			break
		}
	}

	return zeroBits >= n
}

// getAdaptiveDifficulty returns the current difficulty based on recent activity
func getAdaptiveDifficulty() int {
	// This could be enhanced to check recent registration attempts
	// For now, return a configurable default
	difficulty := config.GetPoWDifficulty()
	if difficulty <= 0 {
		return config.DefaultPoWDifficulty()
	}

	// Clamp to min/max values
	if difficulty < config.MinPoWDifficulty() {
		difficulty = config.MinPoWDifficulty()
	}
	if difficulty > config.MaxPoWDifficulty() {
		difficulty = config.MaxPoWDifficulty()
	}

	return difficulty
}
