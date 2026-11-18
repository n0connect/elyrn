package database

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"elyrn/internal/utils"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
)

// ErrUnavailable marks a failure of the database itself (unreachable, restarting, out of
// connections or resources, too slow), never of the request: the caller may retry later. The
// store re-exports it (store.ErrUnavailable) and apperr answers it 503 E_STORE_UNAVAILABLE.
var ErrUnavailable = errors.New("database unavailable")

// SQLSTATEs that mean the database, not the statement, failed (PostgreSQL appendix A): whole
// classes by their two-character prefix, single conditions by their full code.
var (
	unavailableClasses = []string{
		"08", // connection exception
		"53", // insufficient resources (too many connections, out of memory or disk)
	}
	unavailableStates = map[string]struct{}{
		"57P01": {}, // admin_shutdown: the server is stopping
		"57P02": {}, // crash_shutdown
		"57P03": {}, // cannot_connect_now: the server is starting or recovering
		"55P03": {}, // lock_not_available: lock_timeout fired
		"25P03": {}, // idle_in_transaction_session_timeout fired
		"57014": {}, // query_canceled: statement_timeout fired
		// Two transactions met in a lock cycle or a serialization conflict: the one cancelled
		// did nothing wrong and succeeds when retried (a burn racing an account deletion)
		"40P01": {}, // deadlock_detected
		"40001": {}, // serialization_failure
	}
)

// isUnavailable is the one place a driver error is judged to be an outage.
func isUnavailable(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		if _, ok := unavailableStates[pgErr.Code]; ok {
			return true
		}
		for _, class := range unavailableClasses {
			if strings.HasPrefix(pgErr.Code, class) {
				return true
			}
		}
		return false
	}
	var connectErr *pgconn.ConnectError
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, io.ErrUnexpectedEOF) || pgconn.Timeout(err) ||
		errors.As(err, &connectErr) || errors.As(err, &netErr)
}

// classify wraps an outage in ErrUnavailable and leaves every other error as it is.
func classify(err error) error {
	if err == nil || errors.Is(err, ErrUnavailable) || !isUnavailable(err) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// dialector is PostgreSQL's GORM dialector with every error it reports classified: GORM passes
// each statement, BEGIN and COMMIT error through Translate (TranslateError), so no repository
// has to recognise an outage itself.
type dialector struct {
	*postgres.Dialector
}

func (d dialector) Translate(err error) error {
	return classify(d.Dialector.Translate(err))
}

// Every LogError line of the process reduces its error with LogSafe (utils.LogError).
func init() {
	utils.RegisterErrorReducer(LogSafe)
}

// LogSafe returns err in the form a log line may carry it. A driver error's text can hold what
// the statement was given (a lookup, an id, a key) or the database's address and user (a
// connect error), so it is reduced to its class (ErrorClass); every other error is returned
// unchanged.
func LogSafe(err error) error {
	if class, ok := ErrorClass(err); ok {
		return errors.New(class)
	}
	return err
}

// ErrorClass is the one reduction of a driver, connection or outage error to what a log line may
// carry: "database: " and its class (failureDetail: a SQLSTATE, "timed out", "connection
// refused", ...), never its text. ok is false for any other error, whose text the caller judges
// (LogSafe keeps it; middleware.Recover never logs a panic's text at all).
func ErrorClass(err error) (string, bool) {
	var pgErr *pgconn.PgError
	var connectErr *pgconn.ConnectError
	var netErr net.Error
	if errors.As(err, &pgErr) || errors.As(err, &connectErr) || errors.As(err, &netErr) || errors.Is(err, ErrUnavailable) {
		return "database: " + failureDetail(err), true
	}
	return "", false
}
