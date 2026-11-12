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

var (
	DB *gorm.DB
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

// RetentionStatementTimeout bounds one retention statement: a bulk delete after a long pause may
// take longer than a request's statement, so retention runs under LongTransaction with this.
const RetentionStatementTimeout = time.Minute

// migrationStatementTimeout bounds one schema statement at startup
const migrationStatementTimeout = 5 * time.Minute

// pgMilliseconds spells a duration as a PostgreSQL integer setting in milliseconds.
func pgMilliseconds(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// ConnectionURL builds the PostgreSQL URL with every component escaped, so credentials can
// contain any character without altering the connection parameters (no DSN injection).
func ConnectionURL() string {
	query := url.Values{}
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

// Open builds the GORM handle every repository uses: driver errors classified (dialector), every
// statement and transaction under its client-side deadline, and the bounded pool. It does not
// connect yet; Init proves the connection.
func Open(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(dialector{postgres.Open(dsn).(*postgres.Dialector)}, &gorm.Config{
		Logger:                    logger.Default.LogMode(gormLogLevel()),
		TranslateError:            true, // Surfaces unique violations as gorm.ErrDuplicatedKey, outages as ErrUnavailable
		DisableAutomaticPing:      true,
		DefaultContextTimeout:     statementDeadline,
		DefaultTransactionTimeout: transactionDeadline,
	})
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
