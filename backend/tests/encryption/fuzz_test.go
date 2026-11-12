package encryption

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"testing"

	"elyrn/internal/encryption"
	"elyrn/tests/testutil"

	"github.com/google/uuid"
)

// Run one with: go test -tags test -run '^$' -fuzz '^FuzzOpenWithKeyID$' -fuzztime 60s ./tests/encryption

const (
	// fuzzOldKeyID names the retired master key the fuzzed key set also holds
	fuzzOldKeyID = "old-1"
	// fuzzPlain is the record the genuine ciphertext seals (a peer public key's shape)
	fuzzPlain = "5RnU1Lh-_CuOr8VzbLd0OGx4uFmd9YeLM2YysXB2Bx4"
	// masterKeyBytes is one master key's size
	masterKeyBytes = 32
)

// setupFuzzKeys configures an active and one old master key (fresh CSPRNG material) and loads them.
func setupFuzzKeys(f *testing.F) {
	testutil.SetupTestEnv(f)
	old := make([]byte, masterKeyBytes)
	if _, err := rand.Read(old); err != nil {
		f.Fatalf("crypto/rand: %v", err)
	}
	f.Setenv("MASTER_KEY_OLD", fuzzOldKeyID+":"+hex.EncodeToString(old))
	encryption.ResetMasterKeysForTesting()
	if err := encryption.InitMasterKeys(); err != nil {
		f.Fatalf("InitMasterKeys: %v", err)
	}
	f.Cleanup(func() {
		encryption.ResetMasterKeysForTesting()
		testutil.TeardownTestEnv(f)
	})
}

// sealedBytes decodes a stored record the way DecryptWithAAD does (standard base64).
func sealedBytes(text string) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(text)
	return raw, err == nil
}

// FuzzOpenWithKeyID: only configured key ids are known, and a record opens only under the key
// and AAD it was sealed with, and only when its bytes are the sealed bytes (a fuzzer cannot
// forge AES-GCM): what opens is then the sealed plaintext.
func FuzzOpenWithKeyID(f *testing.F) {
	setupFuzzKeys(f)
	activeID := os.Getenv("MASTER_KEY_ACTIVE_ID")
	subject := testutil.NewInternalID(f)
	record := testutil.NewRecordID(f)
	genuine, err := encryption.SealWithActiveKey(fuzzPlain, encryption.BuildAAD(subject, record, encryption.FieldPeerPublicKey, encryption.PurposeStoredRecord))
	if err != nil {
		f.Fatalf("SealWithActiveKey: %v", err)
	}
	genuineRaw, _ := sealedBytes(genuine)
	for _, seed := range [][2]string{{activeID, genuine}, {fuzzOldKeyID, genuine}, {activeID, genuine[:len(genuine)-4]},
		{activeID, genuine + "===="}, {"", ""}, {activeID + " ", genuine}, {"../" + activeID, genuine}} {
		f.Add(seed[0], seed[1], subject, uint8(encryption.FieldPeerPublicKey))
	}
	f.Fuzz(func(t *testing.T, keyID, text, aadSubject string, field uint8) {
		configured := keyID == activeID || keyID == fuzzOldKeyID
		if encryption.HasMasterKey(keyID) != configured {
			t.Fatalf("HasMasterKey(%q) = %v", keyID, !configured)
		}
		aad := encryption.BuildAAD(aadSubject, record, encryption.Field(field), encryption.PurposeStoredRecord)
		plain, ok, err := encryption.OpenWithKeyID(keyID, text, aad)
		if ok != configured {
			t.Fatalf("OpenWithKeyID(%q) known=%v", keyID, ok)
		}
		if !ok || err != nil {
			return
		}
		raw, decoded := sealedBytes(text)
		if keyID != activeID || !decoded || !bytes.Equal(raw, genuineRaw) || aadSubject != subject ||
			encryption.Field(field) != encryption.FieldPeerPublicKey || plain != fuzzPlain {
			t.Fatalf("record %q opened under key %q, subject %q, field %d", text, keyID, aadSubject, field)
		}
	})
}

// FuzzSealRoundTrip: any text sealed under the active key opens to itself with the same AAD, and
// never with another field, another record or the old key.
func FuzzSealRoundTrip(f *testing.F) {
	setupFuzzKeys(f)
	activeID := os.Getenv("MASTER_KEY_ACTIVE_ID")
	f.Add(fuzzPlain, "subject", make([]byte, 16), uint8(encryption.FieldMemberRef))
	f.Add("", "", []byte{}, uint8(0))
	f.Add("\x00\xff", "\n", bytes.Repeat([]byte{0xff}, 16), uint8(0xff))
	f.Fuzz(func(t *testing.T, text, subject string, recordBytes []byte, field uint8) {
		var record uuid.UUID
		copy(record[:], recordBytes)
		aad := encryption.BuildAAD(subject, record, encryption.Field(field), encryption.PurposeStoredRecord)
		sealed, err := encryption.SealWithActiveKey(text, aad)
		if err != nil {
			t.Fatalf("SealWithActiveKey: %v", err)
		}
		if plain, ok, err := encryption.OpenWithKeyID(activeID, sealed, aad); !ok || err != nil || plain != text {
			t.Fatalf("round trip failed: ok=%v err=%v", ok, err)
		}
		other := record
		other[0] ^= 1
		for name, wrong := range map[string][]byte{
			"field":  encryption.BuildAAD(subject, record, encryption.Field(field+1), encryption.PurposeStoredRecord),
			"record": encryption.BuildAAD(subject, other, encryption.Field(field), encryption.PurposeStoredRecord),
		} {
			if _, _, err := encryption.OpenWithKeyID(activeID, sealed, wrong); err == nil {
				t.Fatalf("opened under another %s", name)
			}
		}
		if _, _, err := encryption.OpenWithKeyID(fuzzOldKeyID, sealed, aad); err == nil {
			t.Fatal("opened under the old key")
		}
	})
}
