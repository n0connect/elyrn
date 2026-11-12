package utils

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"

	"github.com/google/uuid"
)

var validationLogger = NewLogger("VALIDATION")

// ========================================
// INPUT VALIDATION - WHITELIST APPROACH
// ========================================
// Security Strategy: the server never sees message plaintext (E2E), so every
// client field is a fixed-shape token (UUID, base64url key, ciphertext) and is
// whitelisted by exact format before use. Frontend renders text via textContent.

// AccountNumber: 256 bits of CSPRNG output, Base64URL (no padding); Base64URL uses
// A-Z, a-z, 0-9, _, - (RFC 4648 Section 5)
const accountNumberBytes = 32

var (
	accountNumberLength  = base64.RawURLEncoding.EncodedLen(accountNumberBytes)
	accountNumberPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

const (
	// internalIDAlphabet is what internal ids are drawn from (62 characters)
	internalIDAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	// byteValues is how many values one random byte takes
	byteValues = 1 << 8
	// internalIDRejectFrom: bytes at or above the largest multiple of the alphabet size are
	// redrawn, so every character is equally likely (256 % 62 = 8, so 248 and up)
	internalIDRejectFrom = byteValues - byteValues%len(internalIDAlphabet)
	// maxInternalIDRedraws bounds the redraws of one character (RULES.md §8.1); a draw is
	// rejected with probability 8/256, so 64 redraws all fail with probability 2^-320
	maxInternalIDRedraws = 64
	// canonicalUUIDLength is the hyphenated text form, 8-4-4-4-12 (RFC 9562 §4)
	canonicalUUIDLength = 36
	// uuidVersionRandom is the random UUID version (RFC 9562 §5.4)
	uuidVersionRandom = 4
)

const (
	// Invite tokens carry 128 bits of CSPRNG output
	InviteTokenBytes = 16
	// E2E ciphertext: nonce(12) || frame || tag(16), the frame a power of two from 256 to
	// 4096 bytes (frontend/js/crypto.js)
	ciphertextOverhead = cryptoengine.GCMNonceSize + cryptoengine.GCMTagSize
	minFrameBytes      = 256
	maxFrameBytes      = 4096
	MinCiphertextBytes = ciphertextOverhead + minFrameBytes
	// MaxCiphertextBytes is the largest one-to-one ciphertext (MAX_MESSAGE_BYTES may lower it)
	MaxCiphertextBytes = ciphertextOverhead + maxFrameBytes
)

func internalIDLength() (int, error) {
	length := config.GetInternalIDLength()
	if length <= 0 {
		return 0, fmt.Errorf("INTERNAL_ID_LENGTH not configured")
	}
	return length, nil
}

func ValidateUUID(uuid string) bool {
	length, err := internalIDLength()
	if err != nil {
		validationLogger.LogError("ValidateUUID", err)
		return false
	}
	if len(uuid) != length {
		return false
	}
	for i := 0; i < len(uuid); i++ {
		if !isAlphaNumeric(uuid[i]) {
			return false
		}
	}
	return true
}

func GenerateInternalID() (string, error) {
	length, err := internalIDLength()
	if err != nil {
		return "", err
	}

	randomBytes, err := cryptoengine.RandomBytes(length)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		b, err := unbiasedIDByte(randomBytes[i])
		if err != nil {
			return "", err
		}
		result[i] = internalIDAlphabet[int(b)%len(internalIDAlphabet)]
	}

	validationLogger.Debug("GenerateInternalID: generated alphanumeric UUID with CSPRNG, length=%d", length)
	return string(result), nil
}

// unbiasedIDByte returns b, or a fresh CSPRNG byte in its place while b would bias the
// alphabet (rejection sampling), within maxInternalIDRedraws.
func unbiasedIDByte(b byte) (byte, error) {
	for redraw := 0; int(b) >= internalIDRejectFrom; redraw++ {
		if redraw >= maxInternalIDRedraws {
			return 0, fmt.Errorf("internal id: rejection sampling exceeded %d redraws", maxInternalIDRedraws)
		}
		extra, err := cryptoengine.RandomBytes(1)
		if err != nil {
			return 0, fmt.Errorf("failed to generate random bytes: %w", err)
		}
		b = extra[0]
	}
	return b, nil
}

// GenerateAccountNumber generates a 256-bit (32 bytes) CSPRNG account number
// Returns base64url-encoded string (43 characters, no padding)
func GenerateAccountNumber() (string, error) {
	// Generate exactly 32 bytes (256 bits) of CSPRNG
	randomBytes, err := cryptoengine.RandomBytes(accountNumberBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64URL encoding (RFC 4648 Section 5, no padding)
	encoded := base64.RawURLEncoding.EncodeToString(randomBytes)

	validationLogger.Debug("GenerateAccountNumber: generated 43-char base64url account number (256-bit CSPRNG)")
	return encoded, nil
}

// ValidateAccountNumber validates account number format
// Must be exactly 43 base64url characters (A-Z, a-z, 0-9, _, -)
func ValidateAccountNumber(accountNumber string) bool {
	if len(accountNumber) != accountNumberLength {
		return false
	}
	return accountNumberPattern.MatchString(accountNumber)
}

// IsBase64URL reports whether s consists only of the base64url alphabet (RFC 4648 §5, no
// padding). Go's decoders skip CR and LF even in Strict mode, so every base64url input is
// whitelisted by alphabet before it is decoded.
func IsBase64URL(s string) bool {
	return s != "" && accountNumberPattern.MatchString(s)
}

// ParseCanonicalUUIDv4 accepts only lowercase, hyphenated, version-4 UUIDs.
// Rejecting alternate spellings keeps AAD binding and DB keys unambiguous.
func ParseCanonicalUUIDv4(raw string) (uuid.UUID, bool) {
	if len(raw) != canonicalUUIDLength {
		return uuid.Nil, false
	}
	parsed, err := uuid.Parse(raw)
	if err != nil || parsed.Version() != uuidVersionRandom || parsed.Variant() != uuid.RFC4122 || parsed.String() != raw {
		return uuid.Nil, false
	}
	return parsed, true
}

// ValidateInviteToken whitelists a base64url (no padding) 16-byte invite token.
func ValidateInviteToken(token string) ([]byte, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(InviteTokenBytes) || !accountNumberPattern.MatchString(token) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != InviteTokenBytes {
		return nil, false
	}
	return raw, true
}

// ValidateCiphertext whitelists an opaque base64url E2E ciphertext of one of the padded sizes.
// Accepting no other size keeps message length out of storage even if a client skips padding.
func ValidateCiphertext(encoded string) bool {
	maxBytes := config.GetMaxMessageBytes()
	if maxBytes <= 0 {
		validationLogger.Error("ValidateCiphertext: MAX_MESSAGE_BYTES not configured")
		return false
	}
	if len(encoded) < base64.RawURLEncoding.EncodedLen(MinCiphertextBytes) ||
		len(encoded) > base64.RawURLEncoding.EncodedLen(maxBytes) ||
		!accountNumberPattern.MatchString(encoded) {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	return err == nil && len(raw) <= maxBytes && isPaddedFrame(len(raw)-ciphertextOverhead)
}

// Room wire format (docs/architecture/rooms.md): header(162) || n wraps(48 each) || body
// (frame + tag). The header is magic(4) version(1) card(60) ephemeral key(32) commitment(32)
// roster digest(32) n(1). The server must not import internal/e2e (the client protocol), so it
// keeps its own copy of these sizes; e2e checks them against its own at compile time.
const (
	// roomKeyBytes: X25519 keys, HKDF outputs, the commitment and the roster digest
	roomKeyBytes = cryptoengine.X25519KeySize
	// roomCodeBytes: secret(32) || max members(1) || expiry hour(4, big-endian)
	roomCodeBytes  = roomKeyBytes + 1 + 4
	roomCountBytes = 1 // the wrap count n, one byte

	RoomLookupBytes  = roomKeyBytes
	RoomCardBytes    = cryptoengine.GCMNonceSize + roomKeyBytes + cryptoengine.GCMTagSize
	RoomVaultBytes   = cryptoengine.GCMNonceSize + roomCodeBytes + cryptoengine.GCMTagSize
	RoomMessageMagic = "NADR"
	RoomNoteMagic    = "NADN"
	RoomVersion      = 0x01
	// RoomHeaderBytes: magic, version(1), card, ephemeral key, commitment, digest, n
	RoomHeaderBytes  = len(RoomMessageMagic) + 1 + RoomCardBytes + 3*roomKeyBytes + roomCountBytes
	RoomWrapBytes    = roomKeyBytes + cryptoengine.GCMTagSize
	RoomDigestOffset = RoomHeaderBytes - roomCountBytes - roomKeyBytes
)

// DecodeExact whitelists canonical base64url (no padding) of exactly size bytes.
func DecodeExact(encoded string, size int) ([]byte, bool) {
	if size <= 0 || len(encoded) != base64.RawURLEncoding.EncodedLen(size) || !accountNumberPattern.MatchString(encoded) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != size {
		return nil, false
	}
	return raw, true
}

// RoomBlob is what the server can check of a room message or note without any key.
type RoomBlob struct {
	Wraps  int
	Digest []byte // the roster digest the sender encrypted for
}

// RoomMinBlobBytes is the smallest room message or note: one wrap and the smallest frame.
const RoomMinBlobBytes = RoomHeaderBytes + RoomWrapBytes + minFrameBytes + cryptoengine.GCMTagSize

// RoomMaxBlobBytes is the largest room message a room of maxMembers can carry.
func RoomMaxBlobBytes(maxMembers int) int {
	return RoomHeaderBytes + maxMembers*RoomWrapBytes + maxFrameBytes + cryptoengine.GCMTagSize
}

// ParseRoomBlob whitelists a room message or note by structure: magic, version, 1..maxWraps
// wraps, and a body of one of the padded frame sizes (so its length says nothing more).
func ParseRoomBlob(encoded, magic string, maxWraps int) (*RoomBlob, bool) {
	if maxWraps < 1 || maxWraps > config.MaxRoomMembersBound || len(encoded) > base64.RawURLEncoding.EncodedLen(RoomMaxBlobBytes(maxWraps)) ||
		!accountNumberPattern.MatchString(encoded) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) < RoomHeaderBytes || string(raw[:len(magic)]) != magic || raw[len(magic)] != RoomVersion {
		return nil, false
	}
	wraps := int(raw[RoomHeaderBytes-1])
	if wraps < 1 || wraps > maxWraps || !isPaddedFrame(len(raw)-RoomHeaderBytes-wraps*RoomWrapBytes-cryptoengine.GCMTagSize) {
		return nil, false
	}
	return &RoomBlob{Wraps: wraps, Digest: append([]byte(nil), raw[RoomDigestOffset:RoomHeaderBytes-1]...)}, true
}

func isPaddedFrame(n int) bool {
	return n >= minFrameBytes && n <= maxFrameBytes && n&(n-1) == 0
}

func isAlphaNumeric(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
