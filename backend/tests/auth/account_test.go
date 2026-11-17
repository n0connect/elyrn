package auth

import (
	"testing"

	"elyrn/internal/auth"
	"elyrn/tests/testutil"
)

func setupAuthTestEnv(t *testing.T) {
	t.Helper()
	testutil.SetupTestEnv(t)
	t.Cleanup(func() {
		testutil.TeardownTestEnv(t)
	})
}

// TestComputeAccountLookup_Deterministic tests that the same auth key under the
// configured pepper always produces the same lookup value, and different keys differ
func TestComputeAccountLookup_Deterministic(t *testing.T) {
	setupAuthTestEnv(t)

	authKey := testutil.NewAuthKey(t)
	lookup1, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		t.Fatalf("ComputeAccountLookup() failed: %v", err)
	}
	lookup2, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		t.Fatalf("ComputeAccountLookup() failed: %v", err)
	}
	if lookup1 != lookup2 {
		t.Errorf("ComputeAccountLookup() is not deterministic: got %q and %q", lookup1, lookup2)
	}
	if len(lookup1) != 64 {
		t.Errorf("ComputeAccountLookup() length = %d, want 64 (hex-encoded SHA256)", len(lookup1))
	}

	other, err := auth.ComputeAccountLookup(testutil.NewAuthKey(t))
	if err != nil || other == lookup1 {
		t.Fatalf("distinct auth keys produced the same lookup (err=%v)", err)
	}
}
