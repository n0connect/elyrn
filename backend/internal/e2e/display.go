package e2e

// Display values, the twin of crypto.js aura/digitGroups and room-crypto.js safetyNumber/roomAura:
// what people see in the browser is what an agent reports, letter for letter.
//
//	aura          = SHA-256("noaddx/aura" || key): adjective[d0 % 64] "-" noun[d1 % 64], code hex(d2 d3)
//	room aura     = aura of SHA-256("noaddx/room-aura" || room id)
//	safety number = six groups of five digits from SHA-256("noaddx/room/safety/v1" || sorted distinct
//	                member keys [|| "noaddx/room/seats/v1" || u32be(seats)]) (RoomSafetyNumber)

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"elyrn/internal/cryptoengine"

	"github.com/google/uuid"
)

const (
	// "noaddx" in these labels is the protocol namespace, not the product name: it never changes.
	infoAura         = "noaddx/aura"
	infoRoomAura     = "noaddx/room-aura"
	roomSafetyPrefix = "noaddx/room/safety/v1"
	roomSeatsLabel   = "noaddx/room/seats/v1"

	auraWords     = 64
	auraCodeStart = 2
	auraCodeEnd   = 4
	hexPerByte    = 2
	// AuraCodeChars is the length of an aura code: its digest bytes in lowercase hex
	AuraCodeChars    = hexPerByte * (auraCodeEnd - auraCodeStart)
	safetyGroups     = 6
	safetyGroupBytes = 5
	safetyGroupMod   = 100000
)

var (
	auraAdjectives = [auraWords]string{
		"silent", "hollow", "velvet", "ashen", "lunar", "feral", "gilded", "frozen",
		"quiet", "hidden", "solar", "obsidian", "pale", "wild", "ivory", "misty",
		"stark", "radiant", "sable", "cinder", "distant", "faded", "gentle", "hushed",
		"iron", "jade", "kindred", "lucid", "mellow", "nimble", "opal", "polar",
		"quartz", "rusted", "saffron", "tidal", "umbral", "vivid", "woven", "zephyr",
		"amber", "briar", "cobalt", "dusk", "eerie", "frost", "ghost", "hazel",
		"indigo", "jasper", "karst", "lilac", "marble", "neon", "onyx", "prism",
		"quill", "raven", "slate", "thorn", "ultra", "vesper", "winter", "xenon",
	}
	auraNouns = [auraWords]string{
		"ember", "fox", "moth", "wren", "lynx", "comet", "echo", "harbor",
		"iris", "kite", "lotus", "mist", "nova", "orbit", "pike", "quasar",
		"reef", "sage", "tide", "umbra", "vale", "willow", "yarrow", "zenith",
		"atlas", "bloom", "crane", "delta", "ether", "fern", "glade", "heron",
		"isle", "jackal", "koi", "lark", "mesa", "nomad", "oak", "petal",
		"quail", "river", "spire", "thistle", "urchin", "viper", "wolf", "yew",
		"aspen", "birch", "cedar", "dune", "elk", "flint", "grove", "hawk",
		"ibis", "juniper", "kestrel", "lichen", "marsh", "newt", "owl", "pine",
	}
)

// Aura is the key-derived name people see next to a key ("silent-ember", code "7f3a").
type Aura struct {
	Name string
	Code string
}

// AuraOf derives the aura of a 32-byte public key.
func AuraOf(publicKey []byte) (Aura, error) {
	if len(publicKey) != keySize {
		return Aura{}, ErrInvalidInput
	}
	digest, err := cryptoengine.SHA256(concat([]byte(infoAura), publicKey))
	if err != nil {
		return Aura{}, err
	}
	return Aura{
		Name: auraAdjectives[int(digest[0])%auraWords] + "-" + auraNouns[int(digest[1])%auraWords],
		Code: hex.EncodeToString(digest[auraCodeStart:auraCodeEnd]),
	}, nil
}

// IsAuraCode reports whether code has the shape AuraOf gives a code: AuraCodeChars lowercase hex.
func IsAuraCode(code string) bool {
	if len(code) != AuraCodeChars {
		return false
	}
	_, err := hex.DecodeString(code)
	return err == nil && strings.ToLower(code) == code
}

// RoomAura is the name a room is shown under; every member derives the same one.
func RoomAura(roomID uuid.UUID) (Aura, error) {
	if roomID == uuid.Nil {
		return Aura{}, ErrInvalidInput
	}
	digest, err := cryptoengine.SHA256(concat([]byte(infoRoomAura), roomID[:]))
	if err != nil {
		return Aura{}, err
	}
	return AuraOf(digest)
}

// RoomSafetyNumber is what members compare on another channel: equal digits, equal member keys
// and, when they differ from the keys, equal seats (room-crypto.js safetyNumber):
//
//	digest = SHA-256("noaddx/room/safety/v1" || distinct member keys (ascending bytes)
//	                 [|| "noaddx/room/seats/v1" || u32be(seats)])
//
// seats is every row the server serves in the member list, duplicates and cards that do not open
// included. The bracketed part is appended only when seats differs from the number of distinct
// keys, so a room where every card opens to its own key keeps the number it always had, and a room
// where two seats claim one key (or a card does not open) shows other digits.
func RoomSafetyNumber(publicKeys [][]byte, seats int) ([]string, error) {
	if len(publicKeys) == 0 || len(publicKeys) > MaxRoomMembers || seats < 0 || uint64(seats) > math.MaxUint32 {
		return nil, ErrInvalidInput
	}
	raws := make([][]byte, 0, len(publicKeys))
	for _, key := range publicKeys {
		if len(key) != keySize {
			return nil, ErrInvalidInput
		}
		raws = append(raws, key)
	}
	sort.Slice(raws, func(i, j int) bool { return bytes.Compare(raws[i], raws[j]) < 0 })
	raws = slices.CompactFunc(raws, bytes.Equal)
	parts := append([][]byte{[]byte(roomSafetyPrefix)}, raws...)
	if seats != len(raws) {
		parts = append(parts, []byte(roomSeatsLabel), binary.BigEndian.AppendUint32(nil, uint32(seats)))
	}
	digest, err := cryptoengine.SHA256(concat(parts...))
	if err != nil {
		return nil, err
	}
	return digitGroups(digest), nil
}

// digitGroups renders six groups of five digits from the first 30 bytes of a digest.
func digitGroups(digest []byte) []string {
	groups := make([]string, safetyGroups)
	for g := range groups {
		var value uint64
		for _, b := range digest[g*safetyGroupBytes : (g+1)*safetyGroupBytes] {
			value = value<<8 | uint64(b)
		}
		groups[g] = fmt.Sprintf("%05d", value%safetyGroupMod)
	}
	return groups
}
