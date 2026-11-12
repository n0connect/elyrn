package database

import (
	"context"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/utils"

	"github.com/jackc/pgx/v5"
)

// Single-instance operation. The server keeps state in its own memory (the proof-of-work secret
// and spent set, pending registrations, the live-event hub, rate limits), so two servers on one
// database behind one address would each be wrong. The first one holds a session-level advisory
// lock on a dedicated connection for its whole life; a second one is refused at start
// (E_SECOND_INSTANCE). If that session ends, the lock is gone with it and another server could
// take it: the holder then stops (E_INSTANCE_LOCK_LOST) instead of re-acquiring, because
// between the loss and a re-acquisition a second server may already have started; its restart
// policy starts it again and the new process takes the lock or is refused.
//
// Lost is not unreachable. A database that is paused, overloaded or briefly cut off has not
// ended the session: it still holds the lock, and exiting would throw away every in-memory
// state above for nothing (requests already answer 503 E_STORE_UNAVAILABLE while the database
// does not answer, and the health endpoint 503). So the watcher must never end the session by
// checking it. With pgx a ping under a context deadline does exactly that: when the deadline
// passes, pgx expires the socket and closes the connection (pgconn: DeadlineContextWatcherHandler,
// then asyncClose on the failed read), and PostgreSQL ends the session and releases the lock as
// soon as it notices. The ping therefore has no deadline of its own: it ends when the database
// answers, when the connection breaks, or when Release cancels the watcher (shutdown, where
// closing is the point). A ping that has not answered within instanceLockSlow is reported once
// per outage (E_INSTANCE_LOCK_UNREACHABLE) and the server keeps serving; the lock counts as
// lost only when the driver reports the connection closed (the server terminated the session,
// PostgreSQL restarted, the socket broke). A ping that failed on a connection pgx kept open
// leaves the session alive and counts as unreachable too.
//
// Residual risk: a network partition, where this server cannot know whether its session still
// holds the lock. Chosen: keep serving until the connection is known to be gone. A second
// instance can start only once PostgreSQL has really released the lock, that is once it ended
// the session; while partitioned this server reaches neither the lock nor (on the same path)
// the pool, so it answers 503 and its memory changes nothing stored. The partition ends in one
// of two ways: the ping answers (the session was alive: nobody else could have held the lock),
// or the socket is reset or times out (TCP retransmission gives up after about 15 minutes with
// Linux defaults) and the server stops with E_INSTANCE_LOCK_LOST. PostgreSQL notices a vanished
// peer only through TCP keepalive (2 hours by default), so with default settings this server
// gives up long before the lock could pass to another; only a PostgreSQL whose
// tcp_keepalives_* settings drop peers faster than the client's retransmission timeout, during
// a partition of the lock's connection alone, leaves a window in which two servers could run.
// Exiting on every unanswered ping would close that window only by turning every database
// pause into a restart that loses all in-memory state, which is the defect this design fixes.
const (
	// instanceLockKey names the lock ("elyrnONE" in ASCII); migrationLockKey is a different key
	instanceLockKey int64 = 0x656c79726e4f4e45
	// instanceLockCheck is how often the lock's connection is pinged
	instanceLockCheck = 10 * time.Second
	// instanceLockSlow is how long a ping may go unanswered before the database is reported
	// unreachable (background work's statement deadline)
	instanceLockSlow = statementDeadline
)

// lockTiming is how the watcher paces itself (production: instanceLockCheck, instanceLockSlow).
type lockTiming struct {
	check time.Duration
	slow  time.Duration
}

// InstanceLock is the held single-instance lock.
type InstanceLock struct {
	stop context.CancelFunc
	done chan struct{}
}

// AcquireInstanceLock takes the lock on a new dedicated connection and watches it every
// instanceLockCheck; lost is called once, from the watcher, when the connection is gone. The
// lock is refused with E_SECOND_INSTANCE when another session holds it.
func AcquireInstanceLock(lost func(*opcode.Failure)) (*InstanceLock, *opcode.Failure) {
	return acquireInstanceLock(lost, lockTiming{check: instanceLockCheck, slow: instanceLockSlow})
}

func acquireInstanceLock(lost func(*opcode.Failure), timing lockTiming) (*InstanceLock, *opcode.Failure) {
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
	go lock.watch(watchCtx, conn, lost, timing)
	dbLogger.Info("Single-instance lock held")
	return lock, nil
}

// watch owns conn (pgx connections are not safe for concurrent use): it pings it every
// timing.check until stopped or until the connection is gone, and closes it on the way out,
// which releases the lock.
func (l *InstanceLock) watch(ctx context.Context, conn *pgx.Conn, lost func(*opcode.Failure), timing lockTiming) {
	defer close(l.done)
	defer closeConn(conn)
	ticker := time.NewTicker(timing.check)
	defer ticker.Stop()
	var health lockHealth
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		err := health.probe(ctx, conn, timing.slow)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			health.answered()
		case conn.IsClosed():
			lost(opcode.Fail(opcode.InstanceLockLost, "", failureDetail(err)))
			return
		default:
			health.unanswered()
		}
	}
}

// lockHealth remembers whether the database is reported unreachable, so an outage is logged
// once when it begins and once when it ends, not at every check.
type lockHealth struct {
	down bool
}

// probe pings conn with no deadline of its own (see above: a deadline would end the session)
// and waits for the answer; one that takes longer than slow is reported unreachable while the
// wait goes on. It returns only once the ping has returned, so conn has one user at a time.
func (h *lockHealth) probe(ctx context.Context, conn *pgx.Conn, slow time.Duration) error {
	answered := make(chan error, 1)
	go func() { answered <- conn.Ping(ctx) }()
	timer := time.NewTimer(slow)
	defer timer.Stop()
	select {
	case err := <-answered:
		return err
	case <-timer.C:
		h.unanswered()
	}
	return <-answered
}

func (h *lockHealth) unanswered() {
	if !h.down {
		h.down = true
		utils.LogFailure(opcode.Fail(opcode.InstanceLockUnreachable, "", ""))
	}
}

func (h *lockHealth) answered() {
	if h.down {
		h.down = false
		dbLogger.Info("The database answers on the single-instance lock's connection again; the lock was held throughout")
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
