package database

import (
	"context"
	"time"

	"elyrn/internal/apperr/opcode"

	"github.com/jackc/pgx/v5"
)

// Single-instance operation. The server keeps state in its own memory (the proof-of-work secret
// and spent set, pending registrations, the live-event hub, rate limits), so two servers on one
// database behind one address would each be wrong. The first one holds a session-level advisory
// lock on a dedicated connection for its whole life; a second one is refused at start
// (E_SECOND_INSTANCE). If that connection dies, the lock is gone with it and another server
// could take it: the holder then stops (E_INSTANCE_LOCK_LOST) instead of re-acquiring, because
// between the loss and a re-acquisition a second server may already have started; its restart
// policy starts it again and the new process takes the lock or is refused.
const (
	// instanceLockKey names the lock ("elyrnONE" in ASCII); migrationLockKey is a different key
	instanceLockKey int64 = 0x656c79726e4f4e45
	// instanceLockCheck is how often the lock's connection is proven alive
	instanceLockCheck = 10 * time.Second
)

// InstanceLock is the held single-instance lock.
type InstanceLock struct {
	stop context.CancelFunc
	done chan struct{}
}

// AcquireInstanceLock takes the lock on a new dedicated connection and watches it every
// instanceLockCheck; lost is called once, from the watcher, when the connection fails. The
// lock is refused with E_SECOND_INSTANCE when another session holds it.
func AcquireInstanceLock(lost func(*opcode.Failure)) (*InstanceLock, *opcode.Failure) {
	ctx, cancel := context.WithTimeout(context.Background(), statementDeadline)
	defer cancel()
	conn, err := pgx.Connect(ctx, ConnectionURL())
	if err != nil {
		return nil, opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
	}
	var acquired bool
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", instanceLockKey).Scan(&acquired); err != nil {
		closeConn(conn)
		return nil, opcode.Fail(opcode.DBUnreachable, "", failureDetail(err))
	}
	if !acquired {
		closeConn(conn)
		return nil, opcode.Fail(opcode.SecondInstance, "", "")
	}
	watchCtx, stop := context.WithCancel(context.Background())
	lock := &InstanceLock{stop: stop, done: make(chan struct{})}
	go lock.watch(watchCtx, conn, lost)
	dbLogger.Info("Single-instance lock held")
	return lock, nil
}

// watch owns conn (pgx connections are not safe for concurrent use): it pings it until stopped
// or until a ping fails, and closes it on the way out, which releases the lock.
func (l *InstanceLock) watch(ctx context.Context, conn *pgx.Conn, lost func(*opcode.Failure)) {
	defer close(l.done)
	defer closeConn(conn)
	ticker := time.NewTicker(instanceLockCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		pingCtx, cancel := context.WithTimeout(ctx, statementDeadline)
		err := conn.Ping(pingCtx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			lost(opcode.Fail(opcode.InstanceLockLost, "", failureDetail(err)))
			return
		}
	}
}

// Release stops the watcher and closes the lock's connection (the lock goes with it).
func (l *InstanceLock) Release() {
	l.stop()
	<-l.done
}

// closeConn closes a lock connection within the statement bound.
func closeConn(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), statementDeadline)
	defer cancel()
	if err := conn.Close(ctx); err != nil {
		dbLogger.Warn("Closing the single-instance lock connection: %s", failureDetail(err))
	}
}

// Close closes the pool (shutdown, after every request and job has stopped).
func Close() {
	if DB == nil {
		return
	}
	sqlDB, err := DB.DB()
	if err != nil {
		return
	}
	if err := sqlDB.Close(); err != nil {
		dbLogger.Warn("Closing the database pool: %s", failureDetail(err))
	}
}

// Ping runs SELECT 1 on the pool within ctx (the healthcheck).
func Ping(ctx context.Context) error {
	if DB == nil {
		return ErrUnavailable
	}
	var one int
	return DB.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error
}
