# Database Tests

These tests run the real `database.Start` (connection, schema migration, the single-instance
lock) against a real PostgreSQL, plus the startup validation of every environment variable. The
backend migrates its own schema at every start, under a schema version and a migration lock, so
nothing here has to run before it.

## Running

```bash
make test-db                                           # with tests/integration, TEST_DB_* overrides
cd backend && go test -count=1 -tags test ./tests/database -v
go test -tags test ./tests/database -v -run TestMigrate_  # one group
```

Defaults when unset (`tests/testutil/db_helper.go`): `DB_HOST=localhost`, `DB_PORT=5432`,
`DB_USER=postgres`, `DB_PASSWORD=postgres`, `DB_NAME=noaddx_test` (`noaddx` is the stored
database name kept across the rename to elyrn.), `DB_SSL_MODE=disable`. Use a separate local
PostgreSQL, never the bundled one: it holds live data and accepts TLS connections only. `make test`
runs the same tests in Docker against a disposable tmpfs database.

## Tests (20, and one fuzz target)

| Group | Tests |
|---|---|
| Schema (`migration_test.go`) | `TestDatabaseMigration`, `TestUserTableSchema`, `TestChatTableSchema` (no column that links a row to a user: no `user_uuid`, no `created_at`), `TestUserTableIndexes`, `TestDatabaseConstraints`, `TestDatabaseConnection`, `TestDatabaseMasterKey` |
| Session bounds | `TestConnection_BoundsLockWaitsAndIdleTransactions`: `lock_timeout` 5 s, `idle_in_transaction_session_timeout` 30 s |
| Schema version (`lifecycle_test.go`) | `TestMigrate_RefusesASchemaNewerThanThisBinary` (`E_SCHEMA_NEWER`, the stamp stays), `TestMigrate_StampsAnUnversionedDatabase`, `TestMigrate_ConcurrentStartsSerialise` |
| Single-instance lock | `TestInstanceLock_SecondHolderIsRefused` (`E_SECOND_INSTANCE`), `TestInstanceLock_LostConnectionIsReported` (`E_INSTANCE_LOCK_LOST`), `TestInstanceLock_AnUnansweringDatabaseKeepsTheLock` |
| Startup validation (`config_validation_test.go`) | `TestValidateStartupConfig_RejectsOutOfRangeValues`, `TestValidateStartupConfig_ProductionFloors`, `TestValidateStartupConfig_PublicOriginNeedsProduction`, `TestConnectionURL_EscapesCredentials`, `TestStartupRefusal_CodedNamedAndValueFree`, `TestStartupRefusal_ListEntriesByPosition`, `TestLogError_ReducesDriverErrorsToTheirClass` |
| Fuzz (`fuzz_test.go`) | `FuzzValidateStartupConfig` |

## Infrastructure

`tests/testutil/db.go`:

- `StartDatabase` / `InitializeTestDatabase`: the real `database.Start` (migration included);
  the previous test's pool is closed first and this test's pool when it ends, so one pool is open
  at a time. An unreachable database fails the test; it never ends the test binary.
- `CleanupTestData`: empties every table after a test. The database is not emptied before each
  test.
