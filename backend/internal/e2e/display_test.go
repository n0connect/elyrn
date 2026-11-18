package e2e

import (
	"encoding/hex"
	"slices"
	"testing"

	"elyrn/internal/cryptoengine"

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
		got, err := RoomSafetyNumber(keys, len(keys))
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
	if _, err := RoomSafetyNumber(nil, 0); err == nil {
		t.Fatal("RoomSafetyNumber accepted no keys")
	}
	if _, err := RoomSafetyNumber([][]byte{displayKeyA, {1}}, 2); err == nil {
		t.Fatal("RoomSafetyNumber accepted a short key")
	}
	tooMany := make([][]byte, MaxRoomMembers+1)
	for i := range tooMany {
		tooMany[i] = displayKeyA
	}
	if _, err := RoomSafetyNumber(tooMany, len(tooMany)); err == nil {
		t.Fatal("RoomSafetyNumber accepted more keys than a room has seats")
	}
}

// The browser's vector for a disputed room (vectors-js.json safety_number_disputed): the member
// keys of the room vector, served under three cards (two open to one key) and under two.
const (
	disputedSafetyInput   = "6e6f616464782f726f6f6d2f7361666574792f763146bd62f6859f7193131d3dd95b239f4e8f08edb7693367f64cf403d6bd77aa4b5bc792d26c6993ae2dda291548afd38eeb80b67754a47d7f5e0b038b439b266f6e6f616464782f726f6f6d2f73656174732f763100000003"
	undisputedSafetyInput = "6e6f616464782f726f6f6d2f7361666574792f763146bd62f6859f7193131d3dd95b239f4e8f08edb7693367f64cf403d6bd77aa4b5bc792d26c6993ae2dda291548afd38eeb80b67754a47d7f5e0b038b439b266f"
)

var (
	disputedSafetyDigits   = []string{"06715", "65360", "05436", "06981", "25277", "41004"}
	undisputedSafetyDigits = []string{"85841", "84549", "45068", "72184", "50057", "56593"}
)

func TestRoomSafetyNumber_CountsSeatsAsTheBrowserDoes(t *testing.T) {
	a, b := mustDecode(t, roomVectorPublicA), mustDecode(t, roomVectorPublicB)
	for _, tc := range []struct {
		keys   [][]byte
		seats  int
		input  string
		digits []string
	}{
		{[][]byte{a, b}, 3, disputedSafetyInput, disputedSafetyDigits},
		{[][]byte{b, a, a}, 3, disputedSafetyInput, disputedSafetyDigits}, // a key listed twice counts once
		{[][]byte{a, b}, 2, undisputedSafetyInput, undisputedSafetyDigits},
	} {
		got, err := RoomSafetyNumber(tc.keys, tc.seats)
		if err != nil || !slices.Equal(got, tc.digits) {
			t.Fatalf("RoomSafetyNumber(seats %d) = %v, %v; want %v", tc.seats, got, err, tc.digits)
		}
		input, err := hex.DecodeString(tc.input)
		if err != nil {
			t.Fatalf("decode the vector input: %v", err)
		}
		digest, err := cryptoengine.SHA256(input)
		if err != nil || !slices.Equal(digitGroups(digest), tc.digits) {
			t.Fatalf("the vector's input does not give its digits: %v", err)
		}
	}
	if _, err := RoomSafetyNumber([][]byte{a, b}, -1); err == nil {
		t.Fatal("a negative seat count was accepted")
	}
}
