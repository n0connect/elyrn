package integration

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"elyrn/internal/encryption"
	"elyrn/internal/models"
)

func health(t *testing.T, mux http.Handler, peer string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, models.PathHealth, nil)
	r.RemoteAddr = peer
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	return rr
}

// The healthcheck touches the database (a backend whose database is gone is not healthy),
// answers loopback peers only, and never says more than its status.
func TestHealth_LoopbackOnlyAndDatabaseBacked(t *testing.T) {
	mux := setup(t)
	for _, peer := range []string{"127.0.0.1:40000", "[::1]:40000"} {
		rr := health(t, mux, peer)
		if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
			t.Fatalf("healthy from %s: %d %q", peer, rr.Code, rr.Body.String())
		}
	}
	// Any other peer (nginx's address included) is told the path does not exist
	if rr := health(t, mux, "172.29.73.10:40000"); rr.Code != http.StatusNotFound {
		t.Fatalf("health from a non-loopback peer: %d", rr.Code)
	}

	restore := breakDatabase(t)
	if rr := health(t, mux, "127.0.0.1:40000"); rr.Code != http.StatusServiceUnavailable || rr.Body.Len() != 0 {
		t.Fatalf("health without a database: %d %q", rr.Code, rr.Body.String())
	}
	restore()
	if rr := health(t, mux, "127.0.0.1:40000"); rr.Code != http.StatusOK {
		t.Fatalf("health after the outage: %d", rr.Code)
	}
}

// Shutdown closes the master keys last: a request that still arrives is refused with 503
// instead of sealing a record under a zeroized key.
func TestShutdown_ClosedKeysRefuseInsteadOfSealing(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	t.Cleanup(func() {
		encryption.ResetMasterKeysForTesting()
		if err := encryption.InitMasterKeys(); err != nil {
			t.Errorf("reopen the master keys: %v", err)
		}
	})
	encryption.Close()
	expectStatus(t, alice.createInvite(), http.StatusServiceUnavailable, "invite after the keys closed")
	if n := countWhere(t, &models.Invite{}, "1 = 1"); n != 0 {
		t.Fatalf("%d invites stored after the keys closed", n)
	}
}
