package database

import (
	"testing"
	"time"
)

// A request's database deadlines follow the HTTP write timeout: below the constants, at least
// writeMargin before the write deadline, never below the floor (a write timeout too small for
// it is clamped and reported, never refused: every value the validator admits stays valid).
func TestRequestDeadlines_FollowTheWriteTimeout(t *testing.T) {
	for _, c := range []struct {
		writeTimeout  time.Duration
		statement, tx time.Duration
		clamped       bool
		answersInTime bool
	}{
		{0, statementDeadline, transactionDeadline, false, true}, // no write deadline
		{1 * time.Second, requestDeadlineFloor, requestDeadlineFloor, true, false},
		{13 * time.Second, requestDeadlineFloor, requestDeadlineFloor, true, false},
		{14 * time.Second, 11 * time.Second, 11 * time.Second, false, true},
		{15 * time.Second, 12 * time.Second, 12 * time.Second, false, true}, // the default
		{18 * time.Second, 15 * time.Second, 15 * time.Second, false, true},
		{30 * time.Second, 15 * time.Second, 27 * time.Second, false, true},
		{38 * time.Second, 15 * time.Second, 35 * time.Second, false, true},
		{300 * time.Second, statementDeadline, transactionDeadline, false, true},
	} {
		got, clamped := requestDeadlines(c.writeTimeout)
		if got.statement != c.statement || got.transaction != c.tx || clamped != c.clamped {
			t.Fatalf("write timeout %s: %+v clamped=%v, want statement %s, transaction %s, clamped=%v",
				c.writeTimeout, got, clamped, c.statement, c.tx, c.clamped)
		}
		if got.statement <= statementTimeout {
			t.Fatalf("write timeout %s: the client deadline %s is not above statement_timeout", c.writeTimeout, got.statement)
		}
		if got.statement > statementDeadline || got.transaction > transactionDeadline {
			t.Fatalf("write timeout %s: a request deadline exceeds its constant: %+v", c.writeTimeout, got)
		}
		inTime := c.writeTimeout == 0 || max(got.statement, got.transaction)+writeMargin <= c.writeTimeout
		if c.writeTimeout > 0 {
			// The request's one deadline bounds every statement and transaction of it, and leaves
			// writeMargin before the write deadline whenever the per-statement ones do
			budget, budgetClamped := requestBudget(c.writeTimeout)
			if budget < max(got.statement, got.transaction) || budgetClamped != c.clamped ||
				(budget+writeMargin <= c.writeTimeout) != c.answersInTime {
				t.Fatalf("write timeout %s: request budget %s clamped=%v against %+v", c.writeTimeout, budget, budgetClamped, got)
			}
		}
		if inTime != c.answersInTime {
			t.Fatalf("write timeout %s: the 503 fits before the write deadline: %v, want %v", c.writeTimeout, inTime, c.answersInTime)
		}
	}
}

// Background work keeps the full constants whatever the write timeout.
func TestBackgroundDeadlines_AreTheConstants(t *testing.T) {
	if backgroundDeadlines.statement != statementDeadline || backgroundDeadlines.transaction != transactionDeadline {
		t.Fatalf("background deadlines %+v", backgroundDeadlines)
	}
}
