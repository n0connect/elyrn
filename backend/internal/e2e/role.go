package e2e

// Member roles (docs/architecture/agents.md D10): a short label beside a room member, sealed
// under a key every code holder derives, so the server stores it without reading it.
//
//	K_role = HKDF(S, "noaddx/room/role")
//	plain  = len(1, 0..64) || utf8(role) || zero padding           (exactly 65 bytes)
//	role   = nonce(12) || AES-256-GCM(K_role, plain, AAD "NADL" 0x01 room id(16) target card(60))
//
// The target card is the stored card of the member the role is for, so the server cannot move a
// role to another member. A role grants nothing; it is other people's data, never an instruction.

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"

	"golang.org/x/text/unicode/norm"
)

const (
	// RoleMaxChars and RoleMaxBytes bound a role's text (after the '#'): code points, UTF-8 bytes.
	RoleMaxChars = 16
	RoleMaxBytes = 64

	rolePlainSize = 1 + RoleMaxBytes
	roleBlobSize  = cryptoengine.GCMNonceSize + rolePlainSize + cryptoengine.GCMTagSize
	// "noaddx" in this label is the protocol namespace, not the product name: it never changes.
	infoRoomRole = "noaddx/room/role"
	// roleHyphen and roleUnderscore are the only characters a role may hold besides letters and digits
	roleHyphen     = '-'
	roleUnderscore = '_'
)

// The server checks only a role blob's size, from its own copy (internal/utils/validation.go);
// a mismatch in either direction is a negative constant and fails the build.
const (
	_ = uint(roleBlobSize - utils.RoomRoleBytes)
	_ = uint(utils.RoomRoleBytes - roleBlobSize)
)

var (
	roomRoleMagic = []byte("NADL")
	// reservedRoles are refused whatever their case: the browser shows these words itself
	reservedRoles = [...]string{"owner", "you"}
)

// roleRune is the per-character rule: a letter (\p{L}), a digit (\p{N}), '-' or '_'.
func roleRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == roleHyphen || r == roleUnderscore
}

// ValidateRoleText is the one Go home of the role text rule (the text after the '#'): it returns
// the text in Unicode NFC, which must then be 0..16 code points of letters, digits, '-' and '_',
// at most 64 UTF-8 bytes, and not a reserved word in any case. The empty role means "no role".
// A sealer passes what this returns; an opener accepts only text this returns unchanged.
func ValidateRoleText(text string) (string, error) {
	if !utf8.ValidString(text) {
		return "", ErrInvalidInput
	}
	normalized := norm.NFC.String(text)
	if utf8.RuneCountInString(normalized) > RoleMaxChars || len(normalized) > RoleMaxBytes ||
		strings.IndexFunc(normalized, func(r rune) bool { return !roleRune(r) }) >= 0 {
		return "", ErrInvalidInput
	}
	for _, reserved := range reservedRoles {
		if strings.EqualFold(normalized, reserved) {
			return "", ErrInvalidInput
		}
	}
	return normalized, nil
}

func (r *Room) roleAAD(card []byte) []byte {
	return concat(roomRoleMagic, []byte{roomVersion}, r.ID[:], card)
}

// rolePlain is len || text || zero padding: every role, the empty one included, seals to one size.
func rolePlain(text string) []byte {
	plain := make([]byte, rolePlainSize)
	plain[0] = byte(len(text))
	copy(plain[1:], text)
	return plain
}

// sealRoleWithNonce seals text for the member whose stored card is targetCard under nonce; only
// the interop vectors fix the nonce, SealRole draws it.
func (r *Room) sealRoleWithNonce(targetCard, text string, nonce []byte) (string, error) {
	if normalized, err := ValidateRoleText(text); err != nil || normalized != text {
		return "", ErrInvalidInput
	}
	card, err := decodeExact(targetCard, roomCardSize)
	if err != nil {
		return "", err
	}
	sealed, err := cryptoengine.SealAES256GCM(r.roleKey, nonce, rolePlain(text), r.roleAAD(card))
	if err != nil {
		return "", err
	}
	return encode(concat(nonce, sealed)), nil
}

// SealRole seals a role (as ValidateRoleText returns it; "" clears) for the member whose stored
// card, as the roster serves it, is targetCard.
func (r *Room) SealRole(targetCard, text string) (string, error) {
	nonce, err := cryptoengine.RandomBytes(cryptoengine.GCMNonceSize)
	if err != nil {
		return "", err
	}
	return r.sealRoleWithNonce(targetCard, text, nonce)
}

// OpenRole returns the role sealed in blob for the member whose stored card is targetCard. The
// tag must verify, the length byte be at most 64, every padding byte be zero and the text pass
// ValidateRoleText unchanged; anything else is ErrBadMessage ("no role" to the caller).
func (r *Room) OpenRole(targetCard, blob string) (string, error) {
	raw, err := decodeExact(blob, roleBlobSize)
	if err != nil {
		return "", ErrBadMessage
	}
	card, err := decodeExact(targetCard, roomCardSize)
	if err != nil {
		return "", ErrBadMessage
	}
	plain, err := cryptoengine.DecryptAES256GCM(r.roleKey, raw, r.roleAAD(card))
	if err != nil || len(plain) != rolePlainSize {
		return "", ErrBadMessage
	}
	length := int(plain[0])
	if length > RoleMaxBytes {
		return "", ErrBadMessage
	}
	for _, b := range plain[1+length:] {
		if b != 0 {
			return "", ErrBadMessage
		}
	}
	text := string(plain[1 : 1+length])
	if normalized, err := ValidateRoleText(text); err != nil || normalized != text {
		return "", ErrBadMessage
	}
	return text, nil
}
