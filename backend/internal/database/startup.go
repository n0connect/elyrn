package database

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"syscall"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/models"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Startup wait: the database may still be starting (a host reboot starts every container at
// once), so the first connection is retried with exponential backoff for at most connectWait
// before the start is refused (E_DB_UNREACHABLE); the restart policy then tries again.
const (
	connectWait       = 60 * time.Second
	connectFirstDelay = time.Second
	connectMaxDelay   = 10 * time.Second
	// connectMaxAttempts bounds the loop (RULES.md §8.1); connectWait ends it long before
	connectMaxAttempts = 64
)

// Connect builds the pool with its two handles (DB, BackgroundDB) and proves one connection
// within the startup wait.
func Connect() *opcode.Failure {
	dbLogger.Info("Initializing database connection...")
	db, err := Open(ConnectionURL())
	if err != nil {
		return opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
	}
	if f := waitForDatabase(db); f != nil {
		return f
	}
	background, err := openBackground(db)
	if err != nil {
		return opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
	}
	DB, BackgroundDB = db, background
	dbLogger.Info("Connected to PostgreSQL")
	return nil
}

// waitForDatabase pings until the database answers. Only an outage (isUnavailable: refused,
// starting, unreachable) is retried; a refusal of the request itself (wrong password, unknown
// database, a certificate that does not verify) fails at once, since waiting cannot fix it.
func waitForDatabase(db *gorm.DB) *opcode.Failure {
	sqlDB, err := db.DB()
	if err != nil {
		return opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
	}
	deadline := time.Now().Add(connectWait)
	delay := connectFirstDelay
	for attempt := 1; attempt <= connectMaxAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), statementDeadline)
		err = sqlDB.PingContext(ctx)
		cancel()
		if err == nil {
			return nil
		}
		if !isUnavailable(err) || time.Now().Add(delay).After(deadline) {
			break
		}
		dbLogger.Warn("Database not reachable yet (attempt %d: %s); retrying in %s", attempt, failureDetail(err), delay)
		time.Sleep(delay)
		delay = min(2*delay, connectMaxDelay)
	}
	return opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
}

// failureDetail describes a driver error without its text: pgx and the network name the
// database user, host and address, which never reach the log (zero identifiers).
func failureDetail(err error) string {
	var pgErr *pgconn.PgError
	var invalidCert x509.CertificateInvalidError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &pgErr):
		return "SQLSTATE " + pgErr.Code
	case errors.As(err, &invalidCert) && invalidCert.Reason == x509.Expired:
		return "TLS: the database certificate has expired or is not yet valid; run make certs, then make up"
	case errors.As(err, &invalidCert), errors.As(err, &unknownCA), errors.As(err, &hostErr):
		return "TLS: the database certificate does not verify against PGSSLROOTCERT; run make certs, then make up"
	case errors.As(err, &dnsErr):
		return "the database host name does not resolve"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, context.DeadlineExceeded) || pgconn.Timeout(err):
		return "timed out"
	default:
		return "connection failed"
	}
}

// Schema versioning. The binary that migrates stamps the schema version it migrated to in
// key_checks ("schema-version", a decimal number: no secret, no identifier). A database stamped
// by a newer binary is refused (E_SCHEMA_NEWER) before any statement touches it: an older
// AutoMigrate cannot know what the newer schema needs. A database without a stamp (every one
// from before versioning) is the baseline, migrated and stamped as usual.
const (
	// SchemaVersion is the schema this binary migrates to. Raise it with every change to the
	// models that a previous binary must not run against. 2: file_parts (a binary that does not
	// know the table would never purge it), conversation_members.role, and users.account_hash
	// dropped (a binary that still writes it would fail every registration). Within one version a
	// change is additive only (idx_file_parts_uploader): an older binary of the version runs on it.
	SchemaVersion     = 2
	schemaVersionName = "schema-version"
	// droppedAccountHashColumn: the Argon2id hash of the auth key that registration used to store
	// and nothing read (D-2026-11-18-a); every migration drops it if it is still there
	droppedAccountHashColumn = "account_hash"
	// migrationLockKey: one transaction-level advisory lock serialises instances that migrate at
	// once ("elyrnMIG" in ASCII); it is released with the transaction
	migrationLockKey int64 = 0x656c79726e4d4947
)

// errSchemaNewer rolls the migration transaction back when the stamp is newer
var errSchemaNewer = errors.New("schema newer than this binary")

// Migrate brings the schema to SchemaVersion in one transaction under the migration lock.
func Migrate(db *gorm.DB) *opcode.Failure {
	stored := 0
	err := LongTransaction(db, migrationStatementTimeout, func(tx *gorm.DB) error {
		// The lock waits for another instance's migration, which may take up to the statement bound
		if err := tx.Exec("SET LOCAL lock_timeout = " + pgMilliseconds(migrationStatementTimeout)).Error; err != nil {
			return err
		}
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockKey).Error; err != nil {
			return err
		}
		var err error
		if stored, err = storedSchemaVersion(tx); err != nil {
			return err
		}
		if stored > SchemaVersion {
			return errSchemaNewer
		}
		if err := tx.AutoMigrate(&models.User{}, &models.Invite{}, &models.Conversation{}, &models.ConversationMember{},
			&models.Message{}, &models.KeyCheck{}, &models.Room{}, &models.RoomNote{}, &models.FilePart{}); err != nil {
			return err
		}
		// Idempotent, so a database restored from an older backup is migrated the same way
		if err := tx.Exec("ALTER TABLE " + models.User{}.TableName() + " DROP COLUMN IF EXISTS " + droppedAccountHashColumn).Error; err != nil {
			return err
		}
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "name"}},
			DoUpdates: clause.AssignmentColumns([]string{"value"}),
		}).Create(&models.KeyCheck{Name: schemaVersionName, Value: strconv.Itoa(SchemaVersion)}).Error
	})
	switch {
	case errors.Is(err, errSchemaNewer):
		return opcode.Fail(opcode.SchemaNewer, "", "database schema "+strconv.Itoa(stored)+", this binary "+strconv.Itoa(SchemaVersion))
	case errors.Is(err, errSchemaMarkMalformed):
		return opcode.Fail(opcode.Migrate, "", "the schema-version row in key_checks is not a number")
	case err != nil:
		return opcode.Fail(opcode.Migrate, "", failureDetail(err))
	}
	if stored < SchemaVersion {
		dbLogger.Info("Database schema migrated from version %d to %d", stored, SchemaVersion)
	} else {
		dbLogger.Info("Database migrations completed (schema version %d)", SchemaVersion)
	}
	return nil
}

// errSchemaMarkMalformed: the stamp is not a number (written by hand); nothing is migrated
var errSchemaMarkMalformed = errors.New("schema mark malformed")

// storedSchemaVersion reads the stamp; 0 when the table or the row does not exist yet.
func storedSchemaVersion(tx *gorm.DB) (int, error) {
	var exists bool
	if err := tx.Raw("SELECT to_regclass(?) IS NOT NULL", models.KeyCheck{}.TableName()).Scan(&exists).Error; err != nil {
		return 0, err
	}
	if !exists {
		return 0, nil
	}
	var values []string
	if err := tx.Model(&models.KeyCheck{}).Where("name = ?", schemaVersionName).Pluck("value", &values).Error; err != nil {
		return 0, err
	}
	if len(values) == 0 {
		return 0, nil
	}
	version, err := strconv.Atoi(values[0])
	if err != nil || version < 0 {
		return 0, errSchemaMarkMalformed
	}
	return version, nil
}
