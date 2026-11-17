package database

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"time"

	"elyrn/internal/config"
	"elyrn/internal/utils"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var dbLogger = utils.NewLogger("DATABASE")

// DB serves requests: its client deadlines follow the HTTP write timeout (requestDeadlines).
// BackgroundDB is the same pool under the full client deadlines, for background work that no
// HTTP answer waits for (the startup key check, re-wrapping, the retention mark). Work that
// needs longer still runs under LongTransaction, whose own deadline neither default touches.
var (
	DB           *gorm.DB
	BackgroundDB *gorm.DB
)

// gormLogLevel keeps SQL (and the pseudonyms/lookups bound into it) out of logs
// unless LOG_LEVEL=debug is explicitly requested.
func gormLogLevel() logger.LogLevel {
	if config.GetLogLevel() == "debug" && !config.IsProductionMode() {
		return logger.Info
	}
	return logger.Silent
}

// Connection pool bounds: a flood of requests queues for a connection instead of exhausting
// PostgreSQL's max_connections (default 100)
const (
	maxOpenConns    = 20
	maxIdleConns    = 10
	connMaxLifetime = 30 * time.Minute
)

// Session bounds: a request stuck behind a row lock gives up instead of queueing for ever, a
// transaction left open (stalled client, broken connection) releases its locks and its pooled
// connection, and a statement that runs away is cancelled by the server. Every transaction here
// takes milliseconds, so none of them ever fires in normal use.
const (
	lockTimeout                     = 5 * time.Second
	idleInTransactionSessionTimeout = 30 * time.Second
	statementTimeout                = 10 * time.Second
)

// Client-side deadlines: what the server cannot bound itself (a full pool, a database that does
// not answer at all) is bounded here, for every statement and every transaction on every path.
// A statement's deadline outlasts statement_timeout by clientMargin, so in normal operation the
// server's own cancellation (SQLSTATE 57014) fires first; a transaction's deadline outlasts
// idle_in_transaction_session_timeout for the same reason. Both answer "service unavailable"
// (ErrUnavailable).
const (
	clientMargin        = 5 * time.Second
	statementDeadline   = statementTimeout + clientMargin
	transactionDeadline = idleInTransactionSessionTimeout + clientMargin
)

// Request deadlines. A request stalled on the database must still get its registered 503 out
// before net/http's write deadline (SERVER_WRITE_TIMEOUT_SEC, counted from the end of the
// request's headers): an answer written after it is dropped with the connection, so the client
// sees a cut connection (nginx: a 502) instead of E_STORE_UNAVAILABLE. So a request's statement
// deadline (GORM's DefaultContextTimeout, which also covers the wait for a pooled connection)
// and its transaction deadline are min(their constant above, write timeout - writeMargin),
// computed once at startup from the validated write timeout. They never go below
// requestDeadlineFloor, which keeps the client deadline above the server's statement_timeout
// (in normal operation PostgreSQL's own cancellation still fires first, as above). Every write
// timeout the validator admits (1-300 s) stays valid: one below requestDeadlineFloor +
// writeMargin is not refused but clamped (requestDeadlines reports it, and startup logs it),
// and there a request stalled on the database can still outlive the write deadline. A
// transaction deadline below idle_in_transaction_session_timeout is safe: when it fires the
// driver closes the connection, which ends the session and its locks at once.
const (
	// writeMargin is what a request keeps between its database deadline and the write deadline:
	// the work before its first statement and the writing of the 503
	writeMargin = 3 * time.Second
	// requestDeadlineFloor keeps the client deadline above statement_timeout
	requestDeadlineFloor = statementTimeout + time.Second
)

// clientDeadlines are the two GORM defaults of one handle.
type clientDeadlines struct {
	statement   time.Duration
	transaction time.Duration
}

// backgroundDeadlines are the full constants (BackgroundDB).
var backgroundDeadlines = clientDeadlines{statement: statementDeadline, transaction: transactionDeadline}

// requestBudget is a whole request's database budget for a positive write timeout: the write
// timeout less writeMargin, never below requestDeadlineFloor; clamped reports a write timeout
// too short to leave the floor.
func requestBudget(writeTimeout time.Duration) (budget time.Duration, clamped bool) {
	budget = writeTimeout - writeMargin
	return max(budget, requestDeadlineFloor), budget < requestDeadlineFloor
}

// requestDeadlines derives DB's deadlines from the write timeout (0: none, the constants
// apply); clamped reports a write timeout too short to leave requestDeadlineFloor.
func requestDeadlines(writeTimeout time.Duration) (deadlines clientDeadlines, clamped bool) {
	if writeTimeout <= 0 {
		return backgroundDeadlines, false
	}
	budget, clamped := requestBudget(writeTimeout)
	return clientDeadlines{
		statement:   min(statementDeadline, budget),
		transaction: min(transactionDeadline, budget),
	}, clamped
}

// RequestBudget is the one deadline of a whole request's database work (finding L-03): the
// request deadline middleware starts it at the handler boundary and every statement and
// transaction of that request runs under it (the store binds its repositories to the
// request's context), so a handler that runs several statements still answers its 503 before
// net/http's write deadline. It is the same budget the per-statement and per-transaction
// defaults of DB are cut from, which stay as the backstop of work bound to no request deadline
// (GORM applies its defaults only to a context without one). 0: no write timeout, no request
// deadline. Read from the configuration at each call, like the write timeout itself.
func RequestBudget() time.Duration {
	writeTimeout := config.GetServerWriteTimeout()
	if writeTimeout <= 0 {
		return 0
	}
	// clamped is not an error: Open warns about a clamped budget once at startup; a request
	// only needs the budget itself
	budget, _ := requestBudget(writeTimeout)
	return budget
}

// RetentionStatementTimeout bounds one retention statement: a bulk delete after a long pause may
// take longer than a request's statement, so retention runs under LongTransaction with this.
const RetentionStatementTimeout = time.Minute

// migrationStatementTimeout bounds one schema statement at startup
const migrationStatementTimeout = 5 * time.Minute

// pgMilliseconds spells a duration as a PostgreSQL integer setting in milliseconds.
func pgMilliseconds(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// ApplicationName names the backend's sessions in pg_stat_activity (the pool and the
// single-instance lock alike), so an operator, or the integration tests' connection guard, can
// tell them from any other client of the database. A fixed word: no identifier, no secret.
const ApplicationName = "elyrn-backend"

// ConnectionURL builds the PostgreSQL URL with every component escaped, so credentials can
// contain any character without altering the connection parameters (no DSN injection).
func ConnectionURL() string {
	query := url.Values{}
	query.Set("application_name", ApplicationName)
	query.Set("sslmode", config.GetDBSSLMode())
	query.Set("TimeZone", "UTC")
	query.Set("lock_timeout", pgMilliseconds(lockTimeout))
	query.Set("idle_in_transaction_session_timeout", pgMilliseconds(idleInTransactionSessionTimeout))
	query.Set("statement_timeout", pgMilliseconds(statementTimeout))
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(config.GetDBUser(), config.GetDBPassword()),
		Host:     net.JoinHostPort(config.GetDBHost(), config.GetDBPort()),
		Path:     "/" + config.GetDBName(),
		RawQuery: query.Encode(),
	}
	return u.String()
}

// Open builds the request handle (DB): driver errors classified (dialector), every statement
// and transaction under its request deadline (requestDeadlines of the configured write
// timeout), and the bounded pool. It does not connect yet; Init proves the connection.
func Open(dsn string) (*gorm.DB, error) {
	deadlines, clamped := requestDeadlines(config.GetServerWriteTimeout())
	if clamped {
		dbLogger.Warn("SERVER_WRITE_TIMEOUT_SEC is below %d s: a request's database deadline stays at %d s, so a request stalled on the database may lose its 503 answer",
			seconds(requestDeadlineFloor+writeMargin), seconds(requestDeadlineFloor))
	}
	db, err := openHandle(postgres.Open(dsn), deadlines)
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(maxOpenConns)
	sqlDB.SetMaxIdleConns(maxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)
	return db, nil
}

// openBackground builds BackgroundDB over the pool of the request handle db (no second pool).
func openBackground(db *gorm.DB) (*gorm.DB, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	return openHandle(postgres.New(postgres.Config{Conn: sqlDB}), backgroundDeadlines)
}

// openHandle is the one GORM configuration of both handles; only the deadlines differ.
func openHandle(driver gorm.Dialector, deadlines clientDeadlines) (*gorm.DB, error) {
	return gorm.Open(dialector{driver.(*postgres.Dialector)}, &gorm.Config{
		Logger:                    logger.Default.LogMode(gormLogLevel()),
		TranslateError:            true, // Surfaces unique violations as gorm.ErrDuplicatedKey, outages as ErrUnavailable
		DisableAutomaticPing:      true,
		DefaultContextTimeout:     deadlines.statement,
		DefaultTransactionTimeout: deadlines.transaction,
	})
}

// LongTransaction runs fn in one transaction whose statements may each take up to limit: the
// server's statement_timeout is raised for this transaction only (SET LOCAL), and the client
// deadline with it.
func LongTransaction(db *gorm.DB, limit time.Duration, fn func(tx *gorm.DB) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), limit+clientMargin)
	defer cancel()
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SET LOCAL statement_timeout = " + pgMilliseconds(limit)).Error; err != nil {
			return err
		}
		return fn(tx)
	})
}
