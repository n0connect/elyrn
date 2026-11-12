package contract

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strconv"

	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/identity"
	"elyrn/internal/pow"
	"elyrn/internal/utils"
)

// Every pattern below is an anchored RE2 expression (Go's regexp: linear time in the input, no
// backtracking, so no ReDoS), compiled once at package init from named constants, never from
// request data. Each is plain: character classes, one optional group, counted repeats <= 87.

// Pattern is the whitelist of one string value: its anchored expression, its length bounds
// (checked first, so the expression never sees an oversized value), and, where a regular
// expression cannot say everything (decoded size, padding frames, room structure), a named
// validator that must also accept.
type Pattern struct {
	Name      string
	re        *regexp.Regexp
	MinLen    int
	MaxLen    int
	check     func(string) bool
	CheckName string // the validator's name in the generated document; "" when there is none
}

// Expr is the pattern's source text, for the generated document.
func (p *Pattern) Expr() string { return p.re.String() }

// Accepts reports whether s is inside the length bounds, matches the expression and passes the
// validator.
func (p *Pattern) Accepts(s string) bool {
	if len(s) < p.MinLen || len(s) > p.MaxLen || !p.re.MatchString(s) {
		return false
	}
	return p.check == nil || p.check(s)
}

// IntRange is the whitelist of one integer value: inclusive bounds and an optional validator.
type IntRange struct {
	Name      string
	Min       int64
	Max       int64
	check     func(int64) bool
	CheckName string
}

// Accepts reports whether v is inside the bounds and passes the validator.
func (r *IntRange) Accepts(v int64) bool {
	return v >= r.Min && v <= r.Max && (r.check == nil || r.check(v))
}

// Character classes the patterns are built from. A base64url string (RFC 4648 §5, no padding)
// of n bytes whose n is not a multiple of 3 ends in a character whose unused low bits are zero:
// two bits for n%3 == 2, four for n%3 == 1. Only the canonical encoding passes.
const (
	classBase64URL      = `[A-Za-z0-9_-]`
	classTailTwoZeroes  = `[AEIMQUYcgkosw048]` // alphabet index a multiple of 4
	classTailFourZeroes = `[AQgw]`             // alphabet index a multiple of 16
	classHexLower       = `[0-9a-f]`
	base64BytesPerGroup = 3
	tailTwoZeroBits     = 2 // n%3 that leaves two unused bits
	tailFourZeroBits    = 1 // n%3 that leaves four unused bits

	// exprUUIDv4: lowercase, hyphenated, version nibble 4, variant bits 10 (RFC 9562 §5.4)
	exprUUIDv4 = `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	// exprJWT: a compact JWS (three base64url segments) or nothing (registration phase 1)
	exprJWT = `^(?:[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)?$`
	// exprDecimal: canonical decimal, no sign, no leading zero, no exponent
	exprDecimal = `^(?:0|[1-9][0-9]*)$`
	// exprInteger: a JSON integer literal in canonical form (no fraction, exponent or "-0")
	exprInteger = `^(?:0|-?[1-9][0-9]*)$`
	// exprBase64URL: the alphabet alone, for the variable-length ciphertexts (length is bounded
	// before matching and the validator checks the decoded structure)
	exprBase64URL = `^[A-Za-z0-9_-]+$`

	// maxInt64Digits and maxUint64Digits bound the decimal literals
	maxInt64Digits  = 19
	maxIntLiteral   = maxInt64Digits + 1 // with a minus sign
	uuidTextLength  = 36
	secondsPerHour  = 3600 // room expiries are whole hours since the Unix epoch
	bitsPerByte     = 8
	maxDifficulty   = bitsPerByte * cryptoengine.SHA256Size // leading zero bits a SHA-256 can have
	minDifficulty   = 1
	firstUnixSecond = 1
)

var (
	reInteger = regexp.MustCompile(exprInteger)

	patternUUIDv4 = &Pattern{Name: "uuid-v4", re: regexp.MustCompile(exprUUIDv4),
		MinLen: uuidTextLength, MaxLen: uuidTextLength, check: canonicalUUIDv4, CheckName: "utils.ParseCanonicalUUIDv4"}
	patternKey32       = base64URLExact("base64url-32", identity.KeySize)
	patternInviteToken = base64URLExact("base64url-16", utils.InviteTokenBytes)
	patternRoomCard    = base64URLExact("room-card", utils.RoomCardBytes)
	patternRoomVault   = base64URLExact("room-vault", utils.RoomVaultBytes)
	patternChallenge   = hexExact("hex-challenge", pow.ChallengeBytes)
	patternSalt        = hexExact("hex-salt", pow.SaltBytes)
	patternSolution    = &Pattern{Name: "pow-solution", re: regexp.MustCompile(exprDecimal),
		MinLen: 1, MaxLen: pow.MaxSolutionDigits, check: decimalUint64, CheckName: "canonical uint64"}
	patternPendingToken = &Pattern{Name: "pending-token", re: regexp.MustCompile(exprJWT),
		MinLen: 0, MaxLen: auth.MaxTokenBytes}
	patternMessage = &Pattern{Name: "message-ciphertext", re: regexp.MustCompile(exprBase64URL),
		MinLen:    base64.RawURLEncoding.EncodedLen(utils.MinCiphertextBytes),
		MaxLen:    max(base64.RawURLEncoding.EncodedLen(utils.MaxCiphertextBytes), base64.RawURLEncoding.EncodedLen(utils.RoomMaxBlobBytes(config.MaxRoomMembersBound))),
		check:     messageCiphertext,
		CheckName: fmt.Sprintf("utils.ValidateCiphertext, or utils.ParseRoomBlob(%s, up to %d wraps)", utils.RoomMessageMagic, config.MaxRoomMembersBound)}
	patternNote = &Pattern{Name: "note-blob", re: regexp.MustCompile(exprBase64URL),
		MinLen:    base64.RawURLEncoding.EncodedLen(utils.RoomMinBlobBytes),
		MaxLen:    base64.RawURLEncoding.EncodedLen(utils.RoomMaxBlobBytes(noteWraps)),
		check:     noteBlob,
		CheckName: fmt.Sprintf("utils.ParseRoomBlob(%s, %d wrap)", utils.RoomNoteMagic, noteWraps)}
	// patternSeqQuery is a page cursor's text: canonical decimal of at most 19 digits
	patternSeqQuery = &Pattern{Name: "seq-query", re: regexp.MustCompile(exprDecimal), MinLen: 1, MaxLen: maxInt64Digits}

	rangeSeq        = &IntRange{Name: "seq", Min: chat.FirstSeq, Max: math.MaxInt64}
	rangeAfter      = &IntRange{Name: "after", Min: 0, Max: math.MaxInt64}
	rangeMaxMembers = &IntRange{Name: "room-size", Min: config.MinRoomMembers, Max: config.MaxRoomMembersBound}
	rangeExpiry     = &IntRange{Name: "room-expiry", Min: firstUnixSecond, Max: math.MaxInt64, check: onTheHour, CheckName: "a multiple of 3600"}
	rangeUnixTime   = &IntRange{Name: "unix-seconds", Min: firstUnixSecond, Max: math.MaxInt64}
	rangeTTL        = &IntRange{Name: "pow-ttl", Min: 1, Max: math.MaxInt64}
	rangeDifficulty = &IntRange{Name: "pow-difficulty", Min: minDifficulty, Max: maxDifficulty}
)

// noteWraps: a note is sealed for exactly one addressee
const noteWraps = 1

// base64URLExact builds the pattern of canonical base64url (no padding) of exactly size bytes.
func base64URLExact(name string, size int) *Pattern {
	length := base64.RawURLEncoding.EncodedLen(size)
	expr := fmt.Sprintf(`^%s{%d}$`, classBase64URL, length)
	switch size % base64BytesPerGroup {
	case tailTwoZeroBits:
		expr = fmt.Sprintf(`^%s{%d}%s$`, classBase64URL, length-1, classTailTwoZeroes)
	case tailFourZeroBits:
		expr = fmt.Sprintf(`^%s{%d}%s$`, classBase64URL, length-1, classTailFourZeroes)
	}
	return &Pattern{Name: name, re: regexp.MustCompile(expr), MinLen: length, MaxLen: length,
		check:     func(s string) bool { _, ok := utils.DecodeExact(s, size); return ok },
		CheckName: fmt.Sprintf("utils.DecodeExact(%d)", size)}
}

// hexExact builds the pattern of lowercase hex of exactly size bytes, as the PoW issuer sends it.
func hexExact(name string, size int) *Pattern {
	length := hex.EncodedLen(size)
	return &Pattern{Name: name, re: regexp.MustCompile(fmt.Sprintf(`^%s{%d}$`, classHexLower, length)),
		MinLen: length, MaxLen: length}
}

func canonicalUUIDv4(s string) bool {
	_, ok := utils.ParseCanonicalUUIDv4(s)
	return ok
}

// decimalUint64: the nonce a PoW solver counts with fits a uint64 and is written canonically
func decimalUint64(s string) bool {
	v, err := strconv.ParseUint(s, 10, 64)
	return err == nil && strconv.FormatUint(v, 10) == s
}

// messageCiphertext admits either message format: which one a conversation takes (and a room's
// own seat count) is state, checked by the chat service against the conversation.
func messageCiphertext(s string) bool {
	if utils.ValidateCiphertext(s) {
		return true
	}
	_, ok := utils.ParseRoomBlob(s, utils.RoomMessageMagic, config.MaxRoomMembersBound)
	return ok
}

func noteBlob(s string) bool {
	_, ok := utils.ParseRoomBlob(s, utils.RoomNoteMagic, noteWraps)
	return ok
}

func onTheHour(v int64) bool { return v%secondsPerHour == 0 }

// parseInteger reads a JSON integer literal that already matched exprInteger.
func parseInteger(literal string) (int64, bool) {
	if len(literal) > maxIntLiteral || !reInteger.MatchString(literal) {
		return 0, false
	}
	v, err := strconv.ParseInt(literal, 10, 64)
	return v, err == nil
}
