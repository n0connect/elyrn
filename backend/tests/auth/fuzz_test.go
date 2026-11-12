package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"elyrn/internal/auth"
	"elyrn/internal/identity"
	"elyrn/tests/testutil"

	"github.com/golang-jwt/jwt/v5"
)

// The AccountNumber of the shared Go/JS interop vector (backend/tests/identity,
// frontend/tests): the fuzz worker must derive the same key as the coordinator that
// produced the seed hashes, so this one is fixed rather than drawn from the CSPRNG.
const vectorAccountNumber = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

// Stored hashes are parsed before Argon2id runs: no encoding may panic the server, and a
// hash verifies only for the key it was made from.
func FuzzVerifyAccountNumberHash(f *testing.F) {
	testutil.SetupTestEnv(f)
	f.Cleanup(func() { testutil.TeardownTestEnv(f) })

	authKey, err := identity.DeriveAuthKey(vectorAccountNumber)
	if err != nil {
		f.Fatalf("DeriveAuthKey: %v", err)
	}
	genuine, err := auth.HashAccountNumber(authKey)
	if err != nil {
		f.Fatalf("HashAccountNumber: %v", err)
	}
	other := testutil.NewAuthKey(f)
	f.Add(genuine, authKey)
	f.Add(genuine, other)
	f.Add("argon2id$m=8192$t=1$p=1$$", authKey)
	f.Add("argon2id$m=4294967296$t=1$p=1$00$00", authKey)
	f.Add("", "")

	f.Fuzz(func(t *testing.T, encodedHash, key string) {
		err := auth.VerifyAccountNumberHash(encodedHash, key)
		if err == nil && key != authKey {
			t.Fatalf("hash %q verified for a different key", encodedHash)
		}
	})
}

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
	pendingID, err := auth.GeneratePendingID()
	if err != nil {
		f.Fatalf("GeneratePendingID: %v", err)
	}
	stored := testutil.NewPendingIdentity(f)
	if err := auth.StorePendingRegistration(pendingID, stored); err != nil {
		f.Fatalf("StorePendingRegistration: %v", err)
	}
	genuine, err := auth.SignPendingRegistrationToken(pendingID)
	if err != nil {
		f.Fatalf("SignPendingRegistrationToken: %v", err)
	}
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
