package integration

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"elyrn/internal/chat"
	"elyrn/internal/database"
	"elyrn/internal/encryption"
	"elyrn/internal/models"
	"elyrn/internal/server"
	"elyrn/tests/testutil"
)

// The restore drill (make test-restore) runs this test twice inside the disposable test stack,
// around the backup target's own dump and a restore into an emptied test database:
//
//	seed    first start on an empty database, one account registered; its account number is
//	        written to RESTORE_DRILL_DIR for the second phase
//	verify  a start on the restored dump (key check, migration onto the restored tables), a
//	        login with that account number, and a new registration (the restored users_id_seq
//	        must not hand out an id that exists)
//
// Both phases use the same keys (RESTORE_DRILL_<variable>), as an instance restored with its
// own .env would. Without RESTORE_DRILL the drill does not run: it needs the dump and restore
// steps between its phases.
const (
	envDrillPhase = "RESTORE_DRILL"
	envDrillDir   = "RESTORE_DRILL_DIR"
	drillSeed     = "seed"
	drillVerify   = "verify"
	drillAccount  = "account"
	// drillKeyPrefix carries the drill's keys from make test-restore into both phases
	drillKeyPrefix = "RESTORE_DRILL_"
)

var drillKeys = []string{"JWT_SECRET", "MASTER_KEY_ACTIVE", "ACCOUNT_LOOKUP_PEPPER"}

func TestRestoreDrill(t *testing.T) {
	phase := os.Getenv(envDrillPhase)
	if phase == "" {
		t.Skip("run by make test-restore (RESTORE_DRILL=seed|verify)")
	}
	testutil.SetupTestEnv(t)
	for _, key := range drillKeys {
		value := os.Getenv(drillKeyPrefix + key)
		if value == "" {
			t.Fatalf("%s%s is not set", drillKeyPrefix, key)
		}
		t.Setenv(key, value)
	}
	encryption.ResetMasterKeysForTesting()
	t.Cleanup(encryption.ResetMasterKeysForTesting)
	if f := database.Start(); f != nil {
		t.Fatalf("start: %s", f.Code.ID)
	}
	if err := chat.NewService().VerifyKeys(); err != nil {
		t.Fatalf("key check: %v", err)
	}
	mux := server.NewMux()
	accountFile := filepath.Join(os.Getenv(envDrillDir), drillAccount)

	switch phase {
	case drillSeed:
		u := register(t, mux)
		if err := os.WriteFile(accountFile, []byte(u.accountNumber), 0o600); err != nil {
			t.Fatalf("write the drill account: %v", err)
		}
	case drillVerify:
		raw, err := os.ReadFile(accountFile)
		if err != nil {
			t.Fatalf("read the drill account: %v", err)
		}
		authKey := registeredAuthKey(t, string(raw))
		expectStatus(t, newClient(t, mux).do("POST", models.PathLogin, models.LoginRequest{AuthKey: authKey}),
			http.StatusOK, "login after restore")
		register(t, mux)
	default:
		t.Fatalf("%s must be %s or %s", envDrillPhase, drillSeed, drillVerify)
	}
}
