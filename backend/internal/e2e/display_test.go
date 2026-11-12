package e2e

import (
	"slices"
	"testing"

	"github.com/google/uuid"
)

// Vectors computed independently from frontend/js/crypto.js and room-crypto.js (word lists read
// from crypto.js, SHA-256 from Python's hashlib): keys 0x00..0x1f and 0x20..0x3f.
var (
	displayKeyA  = sequentialBytes(0x00)
	displayKeyB  = sequentialBytes(0x20)
	displayRoom  = uuid.MustParse("00010203-0405-4607-8809-0a0b0c0d0e0f")
	safetyVector = []string{"12664", "43423", "80012", "88165", "40630", "66351"}
)

func sequentialBytes(start byte) []byte {
	out := make([]byte, keySize)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func TestAuraMatchesTheBrowser(t *testing.T) {
	for _, tc := range []struct {
		key        []byte
		name, code string
	}{
		{displayKeyA, "ashen-urchin", "ad59"},
		{displayKeyB, "feral-koi", "acdc"},
	} {
		got, err := AuraOf(tc.key)
		if err != nil || got.Name != tc.name || got.Code != tc.code {
			t.Fatalf("AuraOf = %+v, %v; want %s %s", got, err, tc.name, tc.code)
		}
	}
	room, err := RoomAura(displayRoom)
	if err != nil || room.Name != "lucid-urchin" || room.Code != "3c0c" {
		t.Fatalf("RoomAura = %+v, %v", room, err)
	}
}

func TestRoomSafetyNumberMatchesTheBrowserInAnyOrder(t *testing.T) {
	for _, keys := range [][][]byte{{displayKeyA, displayKeyB}, {displayKeyB, displayKeyA}} {
		got, err := RoomSafetyNumber(keys)
		if err != nil || !slices.Equal(got, safetyVector) {
			t.Fatalf("RoomSafetyNumber = %v, %v", got, err)
		}
	}
}

func TestDisplayRefusesMalformedKeys(t *testing.T) {
	if _, err := AuraOf(displayKeyA[:keySize-1]); err == nil {
		t.Fatal("AuraOf accepted a short key")
	}
	if _, err := RoomAura(uuid.Nil); err == nil {
		t.Fatal("RoomAura accepted the nil id")
	}
	if _, err := RoomSafetyNumber(nil); err == nil {
		t.Fatal("RoomSafetyNumber accepted no keys")
	}
	if _, err := RoomSafetyNumber([][]byte{displayKeyA, {1}}); err == nil {
		t.Fatal("RoomSafetyNumber accepted a short key")
	}
	tooMany := make([][]byte, MaxRoomMembers+1)
	for i := range tooMany {
		tooMany[i] = displayKeyA
	}
	if _, err := RoomSafetyNumber(tooMany); err == nil {
		t.Fatal("RoomSafetyNumber accepted more keys than a room has seats")
	}
}
