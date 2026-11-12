package identity

import (
	"encoding/base64"
	"strings"
	"testing"

	"elyrn/internal/identity"
)

// Run with: go test -tags test -run '^$' -fuzz '^FuzzDeriveFromAccountNumber$' -fuzztime 60s ./tests/identity

// isCanonicalKey reports whether s is canonical base64url (no padding) of exactly one key.
func isCanonicalKey(s string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == identity.KeySize && base64.RawURLEncoding.EncodeToString(raw) == s
}

// FuzzDeriveFromAccountNumber: an account number is accepted only in its canonical spelling
// (43 base64url characters of 32 bytes, unused bits zero), the auth key and the public key
// derive together or not at all, and both are canonical keys the server's own validator takes.
func FuzzDeriveFromAccountNumber(f *testing.F) {
	for _, seed := range []string{vectorAccountNumber, vectorAccountNumber[:42] + "B", vectorAccountNumber + "A",
		vectorAccountNumber[:42], strings.ToUpper(vectorAccountNumber), vectorAccountNumber[:21] + "\n" + vectorAccountNumber[21:42],
		vectorAccountNumber[:42] + "=", "", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, account string) {
		authKey, authErr := identity.DeriveAuthKey(account)
		publicKey, publicErr := identity.DerivePublicKey(account)
		if (authErr == nil) != (publicErr == nil) {
			t.Fatalf("%q: auth key %v but public key %v", account, authErr, publicErr)
		}
		if authErr != nil {
			if identity.ValidateEncodedKey(account) && len(account) == identity.EncodedKeyLength {
				t.Fatalf("%q is a canonical key but was refused as an account number", account)
			}
			return
		}
		if !isCanonicalKey(account) {
			t.Fatalf("the non-canonical account number %q was accepted", account)
		}
		for _, key := range []string{authKey, publicKey} {
			if !isCanonicalKey(key) || !identity.ValidateEncodedKey(key) {
				t.Fatalf("%q derived the non-canonical key %q", account, key)
			}
		}
	})
}

// FuzzValidateEncodedKey: the key validator accepts exactly the canonical spelling of 32 bytes.
func FuzzValidateEncodedKey(f *testing.F) {
	for _, seed := range []string{vectorAccountNumber, vectorAccountNumber[:42] + "B", vectorAccountNumber + "=", "", "\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if identity.ValidateEncodedKey(key) != isCanonicalKey(key) {
			t.Fatalf("ValidateEncodedKey(%q) disagrees with the canonical form", key)
		}
	})
}
