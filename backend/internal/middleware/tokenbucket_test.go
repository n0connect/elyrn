package middleware

import (
	"testing"
	"time"
)

// The bucket's own arithmetic, driven on a clock of the test's choosing through the code Allow
// runs (allowLocked): the configured rate is the real one, never exceeded.

const (
	testRefill = 3 * time.Second
	testTokens = 20
)

var testStart = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func fullBucket(tokens int) *TokenBucket {
	return &TokenBucket{tokens: tokens, maxTokens: tokens, refillRate: testRefill, lastRefill: testStart, lastAccess: testStart}
}

// A partial interval is kept: requests every 2 s against a 3 s refill get a token at 3 s and
// another at 6 s (the old arithmetic restarted the interval at 4 s and gave none at 6 s).
func TestTokenBucket_KeepsPartialRefill(t *testing.T) {
	tb := fullBucket(2)
	granted := 0
	for range 3 {
		if tb.allowLocked(testStart) {
			granted++
		}
	}
	if granted != 2 {
		t.Fatalf("a full bucket of 2 gave %d of 3 requests at one instant, want exactly 2", granted)
	}
	for _, step := range []struct {
		at   time.Duration
		want bool
	}{{2 * time.Second, false}, {4 * time.Second, true}, {5 * time.Second, false}, {6 * time.Second, true}, {8 * time.Second, false}, {9 * time.Second, true}} {
		if got := tb.allowLocked(testStart.Add(step.at)); got != step.want {
			t.Fatalf("at +%v: granted %v, want %v", step.at, got, step.want)
		}
	}
}

// Over a long run the bucket grants exactly its size plus one token per whole interval: as fast
// as configured, no faster.
func TestTokenBucket_RateIsExact(t *testing.T) {
	for _, every := range []time.Duration{time.Second, 2 * time.Second, 1700 * time.Millisecond, 3 * time.Second, 7 * time.Second} {
		tb := fullBucket(testTokens)
		const run = 10 * time.Minute
		granted := 0
		var last time.Duration
		for at := time.Duration(0); at < run; at += every {
			if tb.allowLocked(testStart.Add(at)) {
				granted++
			}
			last = at
		}
		// The clock starts at the first take (the bucket was full); tokens can only come from
		// whole intervals since then, and requests more frequent than the rate drain the bucket
		// (within two minutes here) and then spend every token as it comes
		ceiling := testTokens + int(last/testRefill)
		if granted > ceiling {
			t.Fatalf("every %v: %d granted, more than the configured %d", every, granted, ceiling)
		}
		if every < testRefill && granted != ceiling {
			t.Fatalf("every %v: %d granted, want exactly %d", every, granted, ceiling)
		}
	}
}

// Time spent full earns nothing: after an idle hour the bucket gives its size, and the next token
// comes one whole interval after the burst began, not earlier.
func TestTokenBucket_FullTimeEarnsNothing(t *testing.T) {
	tb := fullBucket(testTokens)
	burst := testStart.Add(time.Hour)
	for i := 0; i < testTokens; i++ {
		if !tb.allowLocked(burst) {
			t.Fatalf("token %d of a full bucket refused", i+1)
		}
	}
	if tb.allowLocked(burst.Add(testRefill - time.Nanosecond)) {
		t.Fatal("a token came back before one interval after the burst")
	}
	if !tb.allowLocked(burst.Add(testRefill)) {
		t.Fatal("no token one interval after the burst")
	}
	if d := tb.deficit(burst.Add(testRefill)); d != testTokens {
		t.Fatalf("deficit %d right after spending the refilled token, want %d", d, testTokens)
	}
	if d := tb.deficit(burst.Add(time.Duration(testTokens+1) * testRefill)); d != 0 {
		t.Fatalf("deficit %d after a full refill, want 0", d)
	}
}
