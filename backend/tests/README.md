# Test Suite

> **Only the real system.** No code, data or flow stands in for another. Tests use the real HTTP
> routes, a real PostgreSQL, real cryptography (real ciphertext) and secrets drawn from the CSPRNG
> on every run. Invalid inputs are made by corrupting a real output. Fixed inputs are only
> published RFC vectors and the Go-JS interop vectors.

## Layout

```
backend/tests/
|-- auth/                # Auth key, sessions, pending registrations (19 tests, 3 fuzz)
|-- database/            # Migration, schema version, instance lock, startup validation, connection bounds (24 tests, 1 fuzz)
|-- encryption/          # Stored-record encryption, key ids, AAD (12 tests, 2 fuzz)
|-- identity/            # HKDF / X25519 RFC vectors, derivations, tag separation (5 tests, 2 fuzz)
|-- integration/         # End-to-end flows over the real route table (137 tests)
|-- middleware/          # JWT, rate limits, trusted proxy, CORS, security headers, recover (30 tests, 3 fuzz)
|-- testutil/            # Shared helpers (below)
`-- utils/               # Validation, SafeMutex, supervised goroutines, logger (12 tests, 3 fuzz)
```

Counts are test functions (`^func Test`, `TestMain` excluded) and fuzz targets, as of 18 Nov 2026.
Across the whole backend there are 378 test functions and 86 fuzz targets; the fuzz list, the
frontend tests and how to run everything are in
[docs/development/testing-and-contributing.md](../../docs/development/testing-and-contributing.md).

Inside `internal/` (no database): `agent` 15, `apperr` 13, `chat` 1, `contract` 12, `cryptoengine` 9
(known answers on the compiled engine), `cryptoengine/equivalence` 8 (both engines in one binary,
`-tags 'test openssl'`), `database` 2, `e2e` 36, `handlers` 1, `mcp` 12, `middleware` 3, `pow` 19,
`realtime` 6, `utils` 2.

### Integration (`tests/integration/`)

| File | What it covers |
|---|---|
| `flows_test.go` (16) | registration with PoW, login by the derived key, invites, messages, burn, sessions, SSE, input whitelist, IDOR |
| `rooms_test.go` (17) | joining by code (`404` without it, other limits refused), seats, late joiners, `412` on a stale roster, notes, leave and burn, expiry |
| `resilience_test.go` (14) | database outages answer `503` (never "invalid credentials", never a logout), stalled and slow requests keep their `503`, a failed sign-up keeps its number, lowered caps and TTLs, clock jumps, expired rows never served, burn racing sends, no driver text in the log |
| `agent_test.go` (13), `agent_send_test.go` (3), `mcp_test.go` (3) | the real `elyrn-agent` and its MCP server against the real server; two agents and a browser-style user in one room |
| `negative_*_test.go` (31) | negative use generated from the route table: refusals without a session, "not yours" and "never existed" byte-equal, order and repetition, limits, cross-protocol confusion, the agent |
| `keys_test.go` (5) | startup key check, pepper commitment, master key re-wrapping |
| `session_test.go` (4), `account_test.go` (2), `lifecycle_test.go` (2), `paging_test.go` (2) | the token only in the cookie, revocation, CSRF, identity deletion, the loopback-only health endpoint, closed keys refuse instead of sealing, `?before=` paging |
| `restore_test.go` (1) | `TestRestoreDrill`, driven by `make test-restore` (seed, then verify) |

`TestMain` (`helpers_test.go`) fails the package when PostgreSQL is unreachable, so nothing is
reported as passed without running. It runs the tests between two counts of the database's
sessions (`connections_test.go`): a pool, server or transaction left open fails the run.

## Running

```bash
make test             # everything, in Docker, against a disposable tmpfs PostgreSQL (ENGINE=openssl|native)
make test-unit        # no database: ./internal/... and tests/{auth,encryption,identity,middleware,utils}
make test-db          # tests/database and tests/integration against a local PostgreSQL (TEST_DB_* overrides)
make test-restore     # the restore drill, in the disposable test stack
```

By hand, from `backend/` (add `openssl` to `-tags` for that engine):

```bash
DB_HOST=127.0.0.1 DB_PORT=5432 go test -p 1 -count=1 -tags test ./tests/...    # -p 1: the packages share one database
go test -tags test ./tests/identity -v                                          # one package
```

The database tests default to `DB_NAME=noaddx_test`, `DB_USER=postgres`,
`DB_PASSWORD=postgres` and `DB_SSL_MODE=disable` (`testutil/db_helper.go`). Never point them at
the bundled database: it holds live data and accepts TLS connections only.

## Test infrastructure (`tests/testutil/`)

| File | Provides |
|---|---|
| `env.go` | `SetupTestEnv` / `TeardownTestEnv`: every variable the server reads, secrets drawn per run |
| `db.go` | `StartDatabase` (the real `database.Start`; closes the previous test's pool first and its own at the end, so one pool is open at a time), `InitializeTestDatabase`, `CleanupTestData` |
| `db_helper.go`, `docker.go` | database variables for host and container runs |
| `values.go` | real generators: account number, auth key, internal ids, record ids, pending identities |
| `answers.go` | `RegisteredAnswer`, `IsAnswer`, `IsWireAnswer`: compare an answer with its registered `apperr` code |
| `stall.go` | `StartStallingProxy`: a TCP proxy that stalls the database on demand |

Database-level details: [tests/database/README.md](database/README.md).
