package pow

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/models"
)

// Every test drives the real issuer and validator: challenges come from GenerateChallenge,
// solutions are brute-forced with SHA-256 exactly like the browser worker does.

// newClientKey returns a fresh CSPRNG client key so per-client rate limits never collide.
func newClientKey(t testing.TB) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return hex.EncodeToString(raw)
}

func issue(t testing.TB) *models.PoWChallenge {
	t.Helper()
	t.Setenv("POW_DIFFICULTY", "18")
	ch, err := GenerateChallenge(newClientKey(t))
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	return ch
}

// search returns the first nonce whose hash does (want=true) or does not (want=false)
// meet the challenge's difficulty.
func search(t testing.TB, ch *models.PoWChallenge, want bool) string {
	t.Helper()
	for nonce := 0; nonce < 1<<26; nonce++ {
		n := strconv.Itoa(nonce)
		sum := sha256.Sum256([]byte(ch.Challenge + n + ch.Salt))
		if HasLeadingZeroBits(sum[:], ch.Difficulty) == want {
			return n
		}
	}
	t.Fatal("nonce search exhausted")
	return ""
}

func solutionFor(ch *models.PoWChallenge, nonce string) *models.PoWSolution {
	return &models.PoWSolution{Challenge: ch.Challenge, Salt: ch.Salt, Solution: nonce,
		Difficulty: ch.Difficulty, Timestamp: ch.Timestamp, TTL: ch.TTL}
}

// accepted reports whether the real validator admits (and spends) the solution.
func accepted(solution *models.PoWSolution) bool {
	return ValidateSolution(solution) == nil
}

func spentEntry(ch *models.PoWChallenge) bool {
	spentMutex.Lock()
	defer spentMutex.Unlock()
	_, ok := spentChallenges[ch.Challenge]
	return ok
}

func spentCount() int {
	spentMutex.Lock()
	defer spentMutex.Unlock()
	return len(spentChallenges)
}

// Target moved (S-03): issuing stores nothing; the salt is the MAC of the echoed fields.
func TestGenerateChallenge_IssuesAuthenticatedChallengeWithoutState(t *testing.T) {
	ch := issue(t)
	if !IsHexOfLen(ch.Challenge, ChallengeBytes) || !IsHexOfLen(ch.Salt, SaltBytes) {
		t.Fatalf("challenge/salt not %d-byte hex: %q %q", ChallengeBytes, ch.Challenge, ch.Salt)
	}
	if ch.Difficulty != 18 || ch.TTL != int64(config.GetPoWChallengeTTL()/time.Second) {
		t.Fatalf("unexpected difficulty/ttl: %d/%d", ch.Difficulty, ch.TTL)
	}
	ok, err := tagMatches(ch.Challenge, ch.Salt, ch.Timestamp, ch.TTL, ch.Difficulty)
	if err != nil || !ok {
		t.Fatalf("issued salt is not the challenge's tag: ok=%v err=%v", ok, err)
	}
	if spentEntry(ch) {
		t.Fatal("an unsolved challenge is in the spent set")
	}
}

func TestValidateSolution_AcceptsRealSolutionExactlyOnce(t *testing.T) {
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	if !accepted(solution) {
		t.Fatal("a real solution was rejected")
	}
	if accepted(solution) {
		t.Fatal("a used challenge was accepted again (replay)")
	}
}

func TestValidateSolution_RejectsNonceBelowDifficulty(t *testing.T) {
	ch := issue(t)
	if accepted(solutionFor(ch, search(t, ch, false))) {
		t.Fatal("a nonce that misses the difficulty was accepted")
	}
	// A failed attempt must not burn the challenge: the real solution still works
	if !accepted(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("real solution rejected after a failed attempt")
	}
}

// Regression: difficulty must come from the server-side entry, never the client.
func TestValidateSolution_IgnoresClientDifficulty(t *testing.T) {
	ch := issue(t)
	forged := solutionFor(ch, search(t, ch, false))
	forged.Difficulty = 0
	if accepted(forged) {
		t.Fatal("client-chosen difficulty=0 was honoured")
	}
}

func TestValidateSolution_RejectsUnissuedChallenge(t *testing.T) {
	ch := issue(t)
	unissued := *ch
	unissued.Challenge = newClientKey(t) // fresh CSPRNG bytes the server never issued
	if accepted(solutionFor(&unissued, search(t, &unissued, true))) {
		t.Fatal("a solution for a challenge the server never issued was accepted")
	}
}

func TestValidateSolution_RejectsMalformedFields(t *testing.T) {
	ch := issue(t)
	nonce := search(t, ch, true)
	cases := []models.PoWSolution{
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: ""},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: nonce + "a"},
		{Challenge: ch.Challenge, Salt: ch.Salt, Solution: "123456789012345678901"},
		{Challenge: ch.Challenge + "00", Salt: ch.Salt, Solution: nonce},
		{Challenge: ch.Challenge, Salt: "ZZ" + ch.Salt[2:], Solution: nonce},
	}
	for i := range cases {
		if accepted(&cases[i]) {
			t.Fatalf("case %d: malformed solution accepted", i)
		}
	}
	if !accepted(solutionFor(ch, nonce)) {
		t.Fatal("malformed attempts must not burn the challenge")
	}
}

func TestValidateSolution_ExpiresAfterTTL(t *testing.T) {
	t.Setenv("POW_CHALLENGE_TTL_SEC", "1")
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	time.Sleep(1100 * time.Millisecond)
	if accepted(solution) {
		t.Fatal("an expired challenge was accepted")
	}
	// Target moved (S-03): nothing is stored per issued challenge, and a refused one is not spent
	if spentEntry(ch) {
		t.Fatal("an expired challenge was recorded as spent")
	}
}

func TestValidateSolution_ConcurrentSubmissionsAcceptOnce(t *testing.T) {
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	var admitted int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := *solution
			if accepted(&s) {
				atomic.AddInt32(&admitted, 1)
			}
		}()
	}
	wg.Wait()
	if admitted != 1 {
		t.Fatalf("%d concurrent submissions accepted, want exactly 1", admitted)
	}
}

func TestGenerateChallenge_RateLimitedPerClient(t *testing.T) {
	t.Setenv("POW_DIFFICULTY", "18")
	client := newClientKey(t)
	for i := 0; i < challengesPerWindow; i++ {
		if _, err := GenerateChallenge(client); err != nil {
			t.Fatalf("request %d within the window rejected: %v", i, err)
		}
	}
	if _, err := GenerateChallenge(client); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("request beyond the window = %v, want rate limit", err)
	}
	if _, err := GenerateChallenge(newClientKey(t)); err != nil {
		t.Fatalf("another client was throttled: %v", err)
	}
}

// Target moved (S-03): cleanup now evicts expired spent challenges (nothing else is stored
// per challenge) and idle limiters.
func TestCleanup_EvictsExpiredSpentChallengesAndIdleLimiters(t *testing.T) {
	t.Setenv("POW_DIFFICULTY", "18")
	client := newClientKey(t)
	ch, err := GenerateChallenge(client)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	if !accepted(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("a real solution was rejected")
	}
	if !spentEntry(ch) {
		t.Fatal("a solved challenge was not recorded as spent")
	}
	// Cleanup is measured at the given instant: kept while unexpired, gone past timestamp+ttl
	cleanupSpentChallenges(time.Now())
	if !spentEntry(ch) {
		t.Fatal("an unexpired spent challenge was evicted (it could be replayed)")
	}
	cleanupSpentChallenges(time.Unix(ch.Timestamp+ch.TTL+1, 0))
	if spentEntry(ch) {
		t.Fatal("expired spent challenge survived cleanup")
	}

	// Limiters are evicted only once idle for limiterIdleTimeout, measured at the given instant
	cleanupInactiveRateLimiters(time.Now())
	rateLimiterMutex.RLock()
	_, kept := challengeRateLimiters[client]
	rateLimiterMutex.RUnlock()
	if !kept {
		t.Fatal("a recently active limiter was evicted")
	}
	cleanupInactiveRateLimiters(time.Now().Add(limiterIdleTimeout + time.Minute))
	rateLimiterMutex.RLock()
	_, kept = challengeRateLimiters[client]
	rateLimiterMutex.RUnlock()
	if kept {
		t.Fatal("an idle limiter survived cleanup past the idle timeout")
	}
}

func TestDifficulty_ClampedToConfiguredRange(t *testing.T) {
	for env, want := range map[string]int{
		"18":  18,
		"21":  21,
		"1":   config.MinPoWDifficulty(),
		"100": config.MaxPoWDifficulty(),
	} {
		t.Setenv("POW_DIFFICULTY", env)
		if got := getAdaptiveDifficulty(); got != want {
			t.Errorf("POW_DIFFICULTY=%s → %d, want %d", env, got, want)
		}
	}
}

// Target moved (S-03): the outstanding-challenge pool is gone; the bounded store is the spent
// set. Filling it for real costs maxSpentChallenges proofs of work, so the test seeds it with
// unexpired entries directly; past the cap a real solution is refused (fail closed) and is not
// burned, and expired entries are purged to make room.
func TestValidateSolution_SpentSetIsBounded(t *testing.T) {
	resetSpent(t)
	ch := issue(t)
	solution := solutionFor(ch, search(t, ch, true))
	live := time.Now().Add(time.Hour).Unix()
	spentMutex.Lock()
	for i := 0; i < maxSpentChallenges; i++ {
		spentChallenges[strconv.Itoa(i)] = live
	}
	spentMutex.Unlock()

	if err := ValidateSolution(solution); !errors.Is(err, ErrCapacity) {
		t.Fatalf("validation at the spent cap = %v, want ErrCapacity", err)
	}
	if n := spentCount(); n != maxSpentChallenges {
		t.Fatalf("spent set holds %d, cap %d", n, maxSpentChallenges)
	}

	past := time.Now().Add(-time.Hour).Unix()
	spentMutex.Lock()
	spentChallenges["0"] = past
	spentMutex.Unlock()
	if err := ValidateSolution(solution); err != nil {
		t.Fatalf("validation after an entry expired = %v, want accepted", err)
	}
}

// resetSpent empties the spent set now and after the test, so seeded entries never leak.
func resetSpent(t *testing.T) {
	t.Helper()
	empty := func() {
		spentMutex.Lock()
		spentChallenges = make(map[string]int64)
		spentMutex.Unlock()
	}
	empty()
	t.Cleanup(empty)
}

// A limiter idle for a whole window has refilled, so dropping it loses nothing. Keeping it
// longer only helps distinct clients (one per Tor circuit) fill the issuer's client cap, which
// then refuses challenges to everyone.
func TestCleanup_EvictsLimitersIdleForOneWindow(t *testing.T) {
	t.Setenv("POW_DIFFICULTY", "18")
	client := newClientKey(t)
	if _, err := GenerateChallenge(client); err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	cleanupInactiveRateLimiters(time.Now().Add(challengeWindow + time.Second))
	rateLimiterMutex.RLock()
	_, kept := challengeRateLimiters[client]
	rateLimiterMutex.RUnlock()
	if kept {
		t.Fatal("a limiter idle for a full window survived cleanup")
	}
}

// ---- S-03: stateless issuing ----

// searchFrom returns the first nonce at or after from that meets the challenge's difficulty.
func searchFrom(t testing.TB, ch *models.PoWChallenge, from int) string {
	t.Helper()
	for nonce := from; nonce < from+(1<<26); nonce++ {
		n := strconv.Itoa(nonce)
		sum := sha256.Sum256([]byte(ch.Challenge + n + ch.Salt))
		if HasLeadingZeroBits(sum[:], ch.Difficulty) {
			return n
		}
	}
	t.Fatal("nonce search exhausted")
	return ""
}

// swapSecret replaces the per-boot secret (as a restart would) and returns the restore step.
func swapSecret(t *testing.T) func() {
	t.Helper()
	if _, err := challengeSecret(); err != nil {
		t.Fatalf("challengeSecret: %v", err)
	}
	other := make([]byte, secretBytes)
	if _, err := rand.Read(other); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	saved := secret
	secret = other
	return func() { secret = saved }
}

func TestValidateSolution_VerifiesWithZeroStoredState(t *testing.T) {
	resetSpent(t)
	ch := issue(t)
	if n := spentCount(); n != 0 {
		t.Fatalf("issuing stored %d entries, want 0", n)
	}
	if !accepted(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("a challenge with no stored entry did not verify")
	}
	if n := spentCount(); n != 1 || !spentEntry(ch) {
		t.Fatalf("after one solution the spent set holds %d (challenge present=%v), want exactly it", n, spentEntry(ch))
	}
}

// Every echoed field is authenticated: changing any one of them fails, even with a nonce that
// really solves the changed challenge/salt, and none of the attempts burns the real challenge.
func TestValidateSolution_RejectsEachTamperedField(t *testing.T) {
	ch := issue(t)
	flip := func(h string) string {
		if h[0] == '0' {
			return "1" + h[1:]
		}
		return "0" + h[1:]
	}
	tampered := map[string]func(c *models.PoWChallenge){
		"challenge":  func(c *models.PoWChallenge) { c.Challenge = flip(c.Challenge) },
		"salt":       func(c *models.PoWChallenge) { c.Salt = flip(c.Salt) },
		"timestamp":  func(c *models.PoWChallenge) { c.Timestamp++ },
		"ttl":        func(c *models.PoWChallenge) { c.TTL++ },
		"difficulty": func(c *models.PoWChallenge) { c.Difficulty-- },
	}
	for field, change := range tampered {
		forged := *ch
		change(&forged)
		if accepted(solutionFor(&forged, search(t, &forged, true))) {
			t.Fatalf("tampered %s accepted", field)
		}
	}
	if !accepted(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("tampering attempts burned the real challenge")
	}
}

// A solved challenge is refused again, also with a different valid nonce.
func TestValidateSolution_RejectsReplayOfSolvedChallenge(t *testing.T) {
	ch := issue(t)
	first := search(t, ch, true)
	if !accepted(solutionFor(ch, first)) {
		t.Fatal("a real solution was rejected")
	}
	n, err := strconv.Atoi(first)
	if err != nil {
		t.Fatalf("nonce %q: %v", first, err)
	}
	if err := ValidateSolution(solutionFor(ch, searchFrom(t, ch, n+1))); !errors.Is(err, ErrInvalidSolution) {
		t.Fatal("a second solution of a spent challenge was not refused as invalid")
	}
}

// Expiry is timestamp+ttl, both authenticated: a challenge issued (by the real issuer) one
// second more than ttl ago is refused, one issued within ttl is accepted.
func TestValidateSolution_ExpiresByTimestampPlusTTL(t *testing.T) {
	const ttl = int64(60)
	old, err := newChallenge(time.Now().Add(-time.Duration(ttl+1)*time.Second), ttl, 18)
	if err != nil {
		t.Fatalf("newChallenge: %v", err)
	}
	if accepted(solutionFor(old, search(t, old, true))) {
		t.Fatal("a challenge past timestamp+ttl was accepted")
	}
	recent, err := newChallenge(time.Now().Add(-time.Duration(ttl/2)*time.Second), ttl, 18)
	if err != nil {
		t.Fatalf("newChallenge: %v", err)
	}
	if !accepted(solutionFor(recent, search(t, recent, true))) {
		t.Fatal("a challenge within timestamp+ttl was rejected")
	}
}

// A challenge issued under another secret (another server, or before a restart) fails.
func TestValidateSolution_RejectsChallengeFromAnotherSecret(t *testing.T) {
	restore := swapSecret(t)
	ch := issue(t)
	restore()
	if accepted(solutionFor(ch, search(t, ch, true))) {
		t.Fatal("a challenge issued under another secret was accepted")
	}
}

// Issuing allocates no per-challenge state: 100,000 challenges leave the spent set empty, and
// the only growth is one limiter per client key (challengesPerWindow challenges each).
func TestGenerateChallenge_IssuingStoresNoPerChallengeState(t *testing.T) {
	const issued = 100000
	t.Setenv("POW_DIFFICULTY", "18")
	resetSpent(t)
	t.Cleanup(func() { cleanupInactiveRateLimiters(time.Now().Add(limiterIdleTimeout + time.Minute)) })
	rateLimiterMutex.RLock()
	before := len(challengeRateLimiters)
	rateLimiterMutex.RUnlock()

	client := ""
	for i := 0; i < issued; i++ {
		if i%challengesPerWindow == 0 {
			client = newClientKey(t)
		}
		if _, err := GenerateChallenge(client); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
	}
	if n := spentCount(); n != 0 {
		t.Fatalf("issuing %d challenges stored %d spent entries, want 0", issued, n)
	}
	rateLimiterMutex.RLock()
	grown := len(challengeRateLimiters) - before
	rateLimiterMutex.RUnlock()
	if grown > issued/challengesPerWindow {
		t.Fatalf("limiters grew by %d for %d clients", grown, issued/challengesPerWindow)
	}
}
