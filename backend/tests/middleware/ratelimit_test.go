//go:build test
// +build test

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/middleware"
	"elyrn/internal/utils"
	"elyrn/tests/testutil"
)

func TestRateLimitMiddleware_WithinLimit(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify
	if !handlerCalled {
		t.Error("Handler should have been called")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status code = %d, want %d", rr.Code, http.StatusOK)
	}
}

// A burst of RATE_LIMIT_MAX_TOKENS (20) requests passes; the next one, sent before a token
// refills (one per 3 s), is refused with 429 and never reaches the handler.
func TestRateLimitMiddleware_ExceedsLimit(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	middleware.ResetRateLimiterForTesting()

	calls := 0
	handler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	serveOnce := func() int {
		req := httptest.NewRequest("POST", "/api/v2/login", nil)
		req.RemoteAddr = "127.0.0.1:54321"
		rr := httptest.NewRecorder()
		handler(rr, req)
		return rr.Code
	}

	for i := 0; i < 20; i++ {
		if code := serveOnce(); code != http.StatusOK {
			t.Fatalf("request %d of the burst: status %d, want 200", i+1, code)
		}
	}
	if code := serveOnce(); code != http.StatusTooManyRequests {
		t.Fatalf("request 21: status %d, want 429", code)
	}
	if calls != 20 {
		t.Fatalf("handler ran %d times, want 20", calls)
	}
}

func TestRateLimitMiddleware_DifferentIPs(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	handlerCalled1 := false
	handlerCalled2 := false

	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr == "127.0.0.1:11111" {
			handlerCalled1 = true
		} else if r.RemoteAddr == "127.0.0.2:22222" {
			handlerCalled2 = true
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)

	// Request from IP1
	req1 := httptest.NewRequest("POST", "/api/v2/login", nil)
	req1.RemoteAddr = "127.0.0.1:11111"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)

	// Request from IP2
	req2 := httptest.NewRequest("POST", "/api/v2/login", nil)
	req2.RemoteAddr = "127.0.0.2:22222"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)

	// Verify both handlers were called (different IPs, separate buckets)
	if !handlerCalled1 {
		t.Error("Handler for IP1 should have been called")
	}
	if !handlerCalled2 {
		t.Error("Handler for IP2 should have been called")
	}
}

func TestRateLimitMiddleware_XRealIP(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()
	middleware.ResetTrustedProxiesForTesting()

	// Trust the reverse proxy IP so X-Real-IP is honored
	t.Setenv("TRUSTED_PROXIES", "127.0.0.1")

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Real-IP", "192.168.1.100") // Trusted proxy header

	rr := httptest.NewRecorder()

	handlerCalled := false
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)
	handler.ServeHTTP(rr, req)

	// Verify handler was called
	if !handlerCalled {
		t.Error("Handler should have been called")
	}

	// Note: We can't easily verify which IP was used for rate limiting
	// without exposing internal state, but the handler should work
}

func TestRateLimitMiddleware_TokenRefill(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)

	// Reset rate limiter to ensure clean state
	middleware.ResetRateLimiterForTesting()

	req := httptest.NewRequest("POST", "/api/v2/login", nil)
	req.RemoteAddr = "127.0.0.1:99999"

	handlerCalled := 0
	testHandler := middleware.RateLimitMiddleware(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled++
		w.WriteHeader(http.StatusOK)
	})

	handler := http.HandlerFunc(testHandler)

	// Make 10 requests
	for i := 0; i < 10; i++ {
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
	}

	// All should succeed (within limit of 20)
	if handlerCalled != 10 {
		t.Errorf("Handler called %d times, want 10", handlerCalled)
	}

	// Wait for token refill (3 seconds)
	time.Sleep(4 * time.Second)

	// Make another request (should succeed after refill)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if handlerCalled != 11 {
		t.Errorf("Handler called %d times after refill, want 11", handlerCalled)
	}
}

// The limiter's memory is bounded at insertion time, not only at the periodic cleanup:
// a flood of new client keys cannot grow it past RATE_LIMIT_MAX_BUCKETS.
func TestRateLimiter_BucketCountIsBoundedAtInsertion(t *testing.T) {
	testutil.SetupTestEnv(t)
	defer testutil.TeardownTestEnv(t)
	t.Setenv("RATE_LIMIT_MAX_BUCKETS", "50")
	middleware.ResetRateLimiterForTesting()
	t.Cleanup(middleware.ResetRateLimiterForTesting)

	for i := 0; i < 1000; i++ {
		if !middleware.AllowKey("flood:" + strconv.Itoa(i)) {
			t.Fatalf("fresh key %d was refused", i)
		}
		if n := middleware.RateLimiterBucketCountForTesting(); n > 50 {
			t.Fatalf("after %d keys the limiter holds %d buckets, cap is 50", i+1, n)
		}
	}
}

// fileBudgetEnv is a budget of three parts per account and a bound of `bound` budgets, on fresh
// maps (the shared limiter's included, to show budgets never land there).
func fileBudgetEnv(t *testing.T, bound int) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() { testutil.TeardownTestEnv(t) })
	t.Setenv("RATE_LIMIT_MAX_BUCKETS", strconv.Itoa(bound))
	t.Setenv(config.EnvFileAccountDailyBytes, strconv.Itoa(fileBudgetParts*utils.FilePartBytes))
	middleware.ResetRateLimiterForTesting()
	middleware.ResetFileBudgetsForTesting()
	t.Cleanup(middleware.ResetRateLimiterForTesting)
	t.Cleanup(middleware.ResetFileBudgetsForTesting)
}

// fileBudgetParts: the budget these tests use; it refills one part per 8 hours, so nothing comes
// back while a test runs
const fileBudgetParts = 3

// spend takes n parts of key's budget, each of which must be granted.
func spend(t *testing.T, key string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if !middleware.FileBudgetOf(key).Allow() {
			t.Fatalf("%s: part %d of %d refused", key, i+1, n)
		}
	}
}

// A budget holds FILE_ACCOUNT_DAILY_BYTES / 262144 parts, a refund gives exactly one back, a
// refund for a budget that is not held creates none, an account without a stream tag gets
// nothing, and budgets never land in the shared limiter.
func TestFileBudget_SizeAndRefund(t *testing.T) {
	fileBudgetEnv(t, 100)
	shared := middleware.RateLimiterBucketCountForTesting()
	spend(t, "size", fileBudgetParts)
	budget := middleware.FileBudgetOf("size")
	if budget.Allow() {
		t.Fatal("a part beyond the budget was granted")
	}
	budget.Refund()
	if !budget.Allow() || budget.Allow() {
		t.Fatal("a refund did not give back exactly one part")
	}
	middleware.FileBudgetOf("never-taken").Refund()
	if _, held := middleware.FileBudgetDeficitForTesting("never-taken"); held {
		t.Fatal("a refund created a budget")
	}
	if middleware.FileBudgetOf("").Allow() {
		t.Fatal("a part was granted without an account")
	}
	if middleware.RateLimiterBucketCountForTesting() != shared {
		t.Fatal("file budgets landed in the shared limiter")
	}
}

// At the bound the budget closest to full goes (ties: the least recently used), never a more
// spent one while a fuller one exists, and the new account is never refused. The evicted
// account regains exactly its deficit, the smallest held.
func TestFileBudget_EvictsTheFullestAtTheBound(t *testing.T) {
	fileBudgetEnv(t, 4)
	spend(t, "spent-3", 3)
	spend(t, "spent-2", 2)
	spend(t, "spent-1-older", 1)
	spend(t, "spent-1-newer", 1)
	deficits := map[string]int{}
	for _, key := range []string{"spent-3", "spent-2", "spent-1-older", "spent-1-newer"} {
		d, held := middleware.FileBudgetDeficitForTesting(key)
		if !held {
			t.Fatalf("%s is not held below the bound", key)
		}
		deficits[key] = d
	}

	spend(t, "newcomer", 1)
	if _, held := middleware.FileBudgetDeficitForTesting("spent-1-older"); held {
		t.Fatal("the least recently used of the fullest budgets survived")
	}
	for _, key := range []string{"spent-3", "spent-2", "spent-1-newer", "newcomer"} {
		if _, held := middleware.FileBudgetDeficitForTesting(key); !held {
			t.Fatalf("%s was evicted although a fuller or older budget was held", key)
		}
	}
	for key, d := range deficits {
		if key != "spent-1-older" && d < deficits["spent-1-older"] {
			t.Fatalf("%s was fuller (deficit %d) than the evicted budget (%d)", key, d, deficits["spent-1-older"])
		}
	}
	if n := middleware.FileBudgetCountForTesting(); n != 4 {
		t.Fatalf("%d budgets held at the bound of 4", n)
	}

	// Coming back, the evicted account has a full budget: it gained exactly its deficit
	spend(t, "spent-1-older", fileBudgetParts)
	if middleware.FileBudgetOf("spent-1-older").Allow() {
		t.Fatalf("the evicted account gained more than its deficit of %d", deficits["spent-1-older"])
	}
	// The most spent budget is still there and still spent
	if middleware.FileBudgetOf("spent-3").Allow() {
		t.Fatal("the most spent budget was replaced by a fresh one")
	}
}

// Taking, giving back and evicting all happen under the map's lock: with accounts churning
// through a full map from many goroutines, the most spent budget is never evicted, never handed
// a part, and never reset; the bound holds. Run it under -race: no synchronisation by sleeping.
func TestFileBudget_ConcurrentUseUnderTheLock(t *testing.T) {
	const bound, churners, rounds, readers = 8, 8, 200, 4
	fileBudgetEnv(t, bound)
	spend(t, "exhausted", fileBudgetParts)

	var wg sync.WaitGroup
	var granted atomic.Int64
	for g := 0; g < churners; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				budget := middleware.FileBudgetOf("churn:" + strconv.Itoa(g) + ":" + strconv.Itoa(i%(bound/2)))
				// Take a part and give it back: a churning budget is never more spent than one part,
				// so the exhausted one stays the least full and must never be the one evicted
				if budget.Allow() {
					budget.Refund()
				}
			}
		}(g)
	}
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				exhausted := middleware.FileBudgetOf("exhausted")
				if exhausted.Allow() {
					granted.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if n := granted.Load(); n != 0 {
		t.Fatalf("the exhausted budget granted %d parts while others churned", n)
	}
	if d, held := middleware.FileBudgetDeficitForTesting("exhausted"); !held || d != fileBudgetParts {
		t.Fatalf("the exhausted budget is held=%v with deficit %d, want %d", held, d, fileBudgetParts)
	}
	if n := middleware.FileBudgetCountForTesting(); n > bound {
		t.Fatalf("%d budgets held, bound is %d", n, bound)
	}
}
