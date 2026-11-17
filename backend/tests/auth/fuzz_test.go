package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"elyrn/internal/auth"
	"elyrn/tests/testutil"

	"github.com/golang-jwt/jwt/v5"
)

// tokenSeeds are the genuine token and its look-alikes: its signature malleations, the same
// claims under another algorithm or issuer, an unsigned one, a truncated one, and hostile strings.
func tokenSeeds(t testing.TB, genuine string, claims auth.Claims) []string {
	t.Helper()
	secret := []byte(os.Getenv("JWT_SECRET"))
	hs512, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	foreign := claims
	foreign.Issuer = "someone-else"
	return append(signatureMalleations(t, genuine), genuine, genuine+"A", genuine[:len(genuine)-1], genuine+"\n", strings.ToUpper(genuine),
		hs512, none, signWithServerSecret(t, foreign), "a.b.c", "..", "", strings.Repeat("A", auth.MaxTokenBytes+1))
}

// FuzzVerifyToken: nothing panics, and only the exact genuine token string verifies (a fuzzer
// cannot forge HMAC-SHA256, and the shape whitelist plus strict decoding leave one spelling of
// each signature: no flipped unused bit, no inserted CR/LF) and it yields the genuine session.
func FuzzVerifyToken(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	subject := testutil.NewInternalID(f)
	const epoch = 3
	genuine, err := auth.SignToken(subject, epoch)
	if err != nil {
		f.Fatalf("SignToken: %v", err)
	}
	pending, err := auth.SignPendingRegistrationToken(subject)
	if err != nil {
		f.Fatalf("SignPendingRegistrationToken: %v", err)
	}
	for _, seed := range append(tokenSeeds(f, genuine, serverClaims(subject, epoch)), pending) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		session, err := auth.VerifyToken(token)
		if err != nil {
			return
		}
		if token != genuine || session.UserUUID != subject || session.SessionEpoch != epoch {
			t.Fatalf("token %q verified as %+v", token, session)
		}
	})
}

// FuzzVerifyPendingToken: only the exact pending token string the server signed verifies (a
// session token or a signature-malleated look-alike never does), and it yields the identity
// phase 1 stored under its pending id.
func FuzzVerifyPendingToken(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() {
		auth.ResetPendingStoreForTesting()
		testutil.TeardownTestEnv(f)
	})
	pendingID, stored, genuine := testutil.SignedPendingToken(f)
	session, err := auth.SignToken(testutil.NewInternalID(f), 0)
	if err != nil {
		f.Fatalf("SignToken: %v", err)
	}
	for _, seed := range append(signatureMalleations(f, genuine), genuine, genuine+"A", genuine[:len(genuine)-1], session, "", "a.b.c") {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		id, got, err := auth.VerifyPendingRegistrationToken(token)
		if err != nil {
			return
		}
		if token != genuine || id != pendingID || got != stored {
			t.Fatalf("token %q verified as pending %q", token, id)
		}
	})
}

// FuzzAccountLookup: a lookup is always 64 lowercase hex characters, deterministic, and matches
// a stored lookup only when the two are equal; an absent account (empty stored lookup) never
// matches any computed lookup.
func FuzzAccountLookup(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })
	authKey := testutil.NewAuthKey(f)
	genuine, err := auth.ComputeAccountLookup(authKey)
	if err != nil {
		f.Fatalf("ComputeAccountLookup: %v", err)
	}
	for _, stored := range []string{genuine, strings.ToUpper(genuine), genuine[1:], "", strings.Repeat("x", len(genuine))} {
		f.Add(authKey, stored)
	}
	f.Add("", "")
	f.Fuzz(func(t *testing.T, key, stored string) {
		lookup, err := auth.ComputeAccountLookup(key)
		if err != nil {
			t.Fatalf("ComputeAccountLookup: %v", err)
		}
		raw, decodeErr := hex.DecodeString(lookup)
		if decodeErr != nil || len(raw) != sha256.Size || hex.EncodeToString(raw) != lookup {
			t.Fatalf("lookup %q is not 32 bytes of lowercase hex", lookup)
		}
		if again, _ := auth.ComputeAccountLookup(key); again != lookup {
			t.Fatal("ComputeAccountLookup is not deterministic")
		}
		if matched := auth.AccountLookupMatches(lookup, stored); matched != (stored != "" && stored == lookup) {
			t.Fatalf("AccountLookupMatches(%q, %q) = %v", lookup, stored, matched)
		}
	})
}
