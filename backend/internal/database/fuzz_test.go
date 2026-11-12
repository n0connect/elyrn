package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzClassify$' -fuzztime 60s ./internal/database

// Error shapes FuzzClassify builds around its SQLSTATE, one per run
const (
	shapePgError = iota
	shapeDeadline
	shapeBadConn
	shapeUnexpectedEOF
	shapePlain
	errorShapes

	// maxClassifyWraps bounds how deep a fuzzed driver error is wrapped
	maxClassifyWraps = 6
	// sqlstateClassLen is the length of a SQLSTATE class prefix
	sqlstateClassLen = 2
)

// outageStates is the oracle (PostgreSQL appendix A, written out independently of errors.go):
// the SQLSTATEs that mean the database failed, not the statement.
var outageStates = map[string]bool{"57P01": true, "57P02": true, "57P03": true, "55P03": true, "25P03": true, "57014": true}

func outageState(code string) bool {
	if outageStates[code] {
		return true
	}
	class := code[:min(len(code), sqlstateClassLen)]
	return len(code) >= sqlstateClassLen && (class == "08" || class == "53")
}

// FuzzClassify wraps arbitrary SQLSTATEs and messages in driver errors of every shape, to any
// depth: an outage (and only an outage) is marked ErrUnavailable, the original error stays
// reachable (errors.Is / errors.As), classifying twice changes nothing, and nil stays nil.
func FuzzClassify(f *testing.F) {
	for _, code := range []string{"08006", "53300", "57P01", "57014", "23505", "40001", "0", "", "08", "5", "57P0"} {
		f.Add(uint8(shapePgError), code, "message", uint8(1))
	}
	for shape := range errorShapes {
		f.Add(uint8(shape), "", "", uint8(0))
	}
	f.Add(uint8(shapePlain), "57P01", "57P01 database unavailable", uint8(maxClassifyWraps))
	f.Fuzz(func(t *testing.T, shape uint8, code, message string, wraps uint8) {
		if classify(nil) != nil {
			t.Fatal("classify(nil) is not nil")
		}
		var base error
		outage := false
		switch shape % errorShapes {
		case shapePgError:
			base, outage = &pgconn.PgError{Code: code, Message: message}, outageState(code)
		case shapeDeadline:
			base, outage = context.DeadlineExceeded, true
		case shapeBadConn:
			base, outage = driver.ErrBadConn, true
		case shapeUnexpectedEOF:
			base, outage = io.ErrUnexpectedEOF, true
		default:
			base = errors.New(code + message)
		}
		err := base
		for range int(wraps) % (maxClassifyWraps + 1) {
			err = fmt.Errorf("%s: %w", message, err)
		}
		classified := classify(err)
		if errors.Is(classified, ErrUnavailable) != outage {
			t.Fatalf("shape %d code %q: unavailable=%v, want %v", shape%errorShapes, code, !outage, outage)
		}
		if !errors.Is(classified, base) || !strings.Contains(classified.Error(), err.Error()) {
			t.Fatalf("classify lost the original error %v", err)
		}
		if again := classify(classified); again.Error() != classified.Error() {
			t.Fatalf("classifying twice changed %q into %q", classified, again)
		}
	})
}
