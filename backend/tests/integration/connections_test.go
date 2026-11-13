package integration

// The connection guard: the integration tests must give back every database connection they
// open. Each test brings the database up with its own pool (testutil.StartDatabase) and closes it
// when it ends; a pool or a connection left open (a test that swaps database.DB, a server it
// starts, a transaction or rows a product path does not release) piles up across the ~130 tests
// of this package until PostgreSQL refuses connections (SQLSTATE 53300, max_connections 100) and
// a later test cannot start at all. The guard counts this database's client sessions before and
// after the whole package and fails the run, naming each leftover by application name, state and
// the first word of its statement (never the statement itself, which can hold values).

import (
	"context"
	"fmt"
	"strings"
	"time"

	"elyrn/internal/database"

	"github.com/jackc/pgx/v5"
)

const (
	// guardApplicationName names the guard's own session (excluded from the count anyway)
	guardApplicationName = "elyrn-test-guard"
	// guardTimeout bounds every exchange of the guard with the database
	guardTimeout = 10 * time.Second
	// guardSettle is how long closed connections get to leave pg_stat_activity: a client's
	// close reaches the server asynchronously
	guardSettle = 5 * time.Second
	// guardPoll is the pause between two counts while they settle
	guardPoll = 100 * time.Millisecond
)

// connectionsQuery lists this database's client sessions other than the guard's own: the
// application name, the state and the statement's first word only.
const connectionsQuery = `SELECT coalesce(application_name, ''), coalesce(state, ''),
	coalesce(split_part(ltrim(query), ' ', 1), '')
	FROM pg_stat_activity
	WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_type = 'client backend'
	ORDER BY 1, 2, 3`

// connectionGuard is the guard's own session to the test database.
type connectionGuard struct {
	conn *pgx.Conn
}

// openConnectionGuard connects with the backend's configuration under the guard's own name.
func openConnectionGuard() (*connectionGuard, error) {
	cfg, err := pgx.ParseConfig(database.ConnectionURL())
	if err != nil {
		return nil, fmt.Errorf("parse the connection URL: %w", err)
	}
	cfg.RuntimeParams["application_name"] = guardApplicationName
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", database.LogSafe(err))
	}
	return &connectionGuard{conn: conn}, nil
}

// sessions is one line per client session of this database other than the guard.
func (g *connectionGuard) sessions() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()
	rows, err := g.conn.Query(ctx, connectionsQuery)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, state, verb string
		if err := rows.Scan(&name, &state, &verb); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("application=%q state=%q statement=%q", name, state, verb))
	}
	return out, rows.Err()
}

// settledAt waits up to guardSettle for the session count to come back to baseline; past it,
// the error lists the sessions still open.
func (g *connectionGuard) settledAt(baseline int) error {
	deadline := time.Now().Add(guardSettle)
	for {
		open, err := g.sessions()
		if err != nil {
			return fmt.Errorf("count sessions: %w", database.LogSafe(err))
		}
		if len(open) <= baseline {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%d database sessions open after the tests, %d before:\n  %s",
				len(open), baseline, strings.Join(open, "\n  "))
		}
		time.Sleep(guardPoll)
	}
}

func (g *connectionGuard) close() {
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()
	_ = g.conn.Close(ctx)
}
