package database

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"elyrn/internal/apperr/opcode"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/tests/testutil"
)

// schemaVersionRow is the key_checks row the migrating binary stamps (a stored name)
const schemaVersionRow = "schema-version"

func startDatabase(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() { testutil.TeardownTestEnv(t) })
	testutil.SetupTestDatabaseEnv()
	if f := database.Start(); f != nil {
		t.Fatalf("start: %s", f.Error())
	}
}

func storedSchemaVersion(t *testing.T) (string, bool) {
	t.Helper()
	var values []string
	if err := database.DB.Model(&models.KeyCheck{}).Where("name = ?", schemaVersionRow).Pluck("value", &values).Error; err != nil {
		t.Fatalf("read the schema version: %v", err)
	}
	if len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func setSchemaVersion(t *testing.T, version int) {
	t.Helper()
	if err := database.DB.Exec("UPDATE key_checks SET value = ? WHERE name = ?", strconv.Itoa(version), schemaVersionRow).Error; err != nil {
		t.Fatalf("stamp the schema version: %v", err)
	}
}

// A database migrated by a newer binary is refused before anything is migrated, and the
// refusal changes nothing (the stamp stays).
func TestMigrate_RefusesASchemaNewerThanThisBinary(t *testing.T) {
	startDatabase(t)
	if got, ok := storedSchemaVersion(t); !ok || got != strconv.Itoa(database.SchemaVersion) {
		t.Fatalf("schema version after migration = %q (%v), want %d", got, ok, database.SchemaVersion)
	}
	newer := database.SchemaVersion + 1
	setSchemaVersion(t, newer)
	t.Cleanup(func() { setSchemaVersion(t, database.SchemaVersion) })

	f := database.Migrate(database.DB)
	if f == nil || f.Code.ID != opcode.SchemaNewer.ID {
		t.Fatalf("a newer schema was migrated: %v", f)
	}
	if got, _ := storedSchemaVersion(t); got != strconv.Itoa(newer) {
		t.Fatalf("the refused migration changed the stamp to %q", got)
	}
}

// Every database from before versioning has no stamp: it is the baseline, migrated and stamped.
func TestMigrate_StampsAnUnversionedDatabase(t *testing.T) {
	startDatabase(t)
	if err := database.DB.Where("name = ?", schemaVersionRow).Delete(&models.KeyCheck{}).Error; err != nil {
		t.Fatalf("remove the stamp: %v", err)
	}
	if f := database.Migrate(database.DB); f != nil {
		t.Fatalf("an unversioned database was refused: %s", f.Error())
	}
	if got, ok := storedSchemaVersion(t); !ok || got != strconv.Itoa(database.SchemaVersion) {
		t.Fatalf("schema version = %q (%v), want %d", got, ok, database.SchemaVersion)
	}
}

// Instances that start at once serialise on the migration lock; both succeed.
func TestMigrate_ConcurrentStartsSerialise(t *testing.T) {
	startDatabase(t)
	const starts = 4
	failures := make(chan *opcode.Failure, starts)
	var wg sync.WaitGroup
	for i := 0; i < starts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			failures <- database.Migrate(database.DB)
		}()
	}
	wg.Wait()
	close(failures)
	for f := range failures {
		if f != nil {
			t.Fatalf("a concurrent migration failed: %s", f.Error())
		}
	}
}

// Exactly one server runs on a database: a second lock holder is refused, and the lock is free
// again once the first lets go.
func TestInstanceLock_SecondHolderIsRefused(t *testing.T) {
	startDatabase(t)
	ignore := func(*opcode.Failure) {}
	first, f := database.AcquireInstanceLock(ignore)
	if f != nil {
		t.Fatalf("first instance refused: %s", f.Error())
	}
	second, f := database.AcquireInstanceLock(ignore)
	if f == nil {
		second.Release()
		first.Release()
		t.Fatal("a second instance acquired the lock")
	}
	if f.Code.ID != opcode.SecondInstance.ID {
		t.Fatalf("second instance: %s, want %s", f.Code.ID, opcode.SecondInstance.ID)
	}
	first.Release()
	third, f := database.AcquireInstanceLock(ignore)
	if f != nil {
		t.Fatalf("the lock was not released: %s", f.Error())
	}
	third.Release()
}

// A holder whose lock connection dies is told (E_INSTANCE_LOCK_LOST) instead of running on
// without the lock.
func TestInstanceLock_LostConnectionIsReported(t *testing.T) {
	startDatabase(t)
	lost := make(chan *opcode.Failure, 1)
	lock, f := database.AcquireInstanceLock(func(f *opcode.Failure) { lost <- f })
	if f != nil {
		t.Fatalf("acquire: %s", f.Error())
	}
	defer lock.Release()
	if err := database.DB.Exec("SELECT pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND pid <> pg_backend_pid()").Error; err != nil {
		t.Fatalf("terminate the lock's connection: %v", err)
	}
	select {
	case f := <-lost:
		if f.Code.ID != opcode.InstanceLockLost.ID {
			t.Fatalf("lost lock reported as %s", f.Code.ID)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the lost lock was never reported")
	}
}
