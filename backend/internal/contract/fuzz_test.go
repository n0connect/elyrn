package contract

import (
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

// One fuzz target per pattern and validator pair: whatever a pattern accepts is canonical,
// so decoding it and encoding it again gives the input back, and nothing panics.
// Run one with: go test -tags test -run '^$' -fuzz '^FuzzPatternUUIDv4$' -fuzztime 30s ./internal/contract

// fuzzBase64 asserts that every accepted value re-encodes to itself (and decodes to a size
// inside [minBytes, maxBytes]).
func fuzzBase64(f *testing.F, p *Pattern, seeds ...string) {
	for _, seed := range seeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s || len(s) < p.MinLen || len(s) > p.MaxLen {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func base64Seeds(t testing.TB, p *Pattern) []string {
	valid := exampleString(t, p)
	return []string{valid, valid + "A", valid[:len(valid)-1], valid[:len(valid)-1] + "B", strings.ToUpper(valid), valid + "=", "", "\n" + valid}
}

func FuzzPatternUUIDv4(f *testing.F) {
	for _, seed := range []string{uuid.NewString(), strings.ToUpper(uuid.NewString()), uuid.Nil.String(), "{" + uuid.NewString() + "}", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternUUIDv4.Accepts(s) {
			return
		}
		id, err := uuid.Parse(s)
		if err != nil || id.String() != s || id.Version() != 4 || id.Variant() != uuid.RFC4122 {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

func FuzzPatternKey32(f *testing.F) { fuzzBase64(f, patternKey32, base64Seeds(f, patternKey32)...) }
func FuzzPatternInviteToken(f *testing.F) {
	fuzzBase64(f, patternInviteToken, base64Seeds(f, patternInviteToken)...)
}
func FuzzPatternRoomCard(f *testing.F) {
	fuzzBase64(f, patternRoomCard, base64Seeds(f, patternRoomCard)...)
}
func FuzzPatternRoomVault(f *testing.F) {
	fuzzBase64(f, patternRoomVault, base64Seeds(f, patternRoomVault)...)
}
func FuzzPatternMessage(f *testing.F) {
	fuzzBase64(f, patternMessage, exampleString(f, patternMessage), roomBlob(f, utils.RoomMessageMagic, 2), roomBlob(f, utils.RoomNoteMagic, 1))
}
func FuzzPatternNote(f *testing.F) {
	fuzzBase64(f, patternNote, exampleString(f, patternNote), roomBlob(f, utils.RoomMessageMagic, 1), roomBlob(f, utils.RoomNoteMagic, 2))
}

// fuzzHex: an accepted challenge or salt is lowercase hex of its exact size.
func fuzzHex(f *testing.F, p *Pattern) {
	valid := exampleString(f, p)
	for _, seed := range []string{valid, strings.ToUpper(valid), valid + "0", valid[1:], ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		raw, err := hex.DecodeString(s)
		if err != nil || hex.EncodeToString(raw) != s || len(s) != p.MaxLen {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func FuzzPatternChallenge(f *testing.F) { fuzzHex(f, patternChallenge) }
func FuzzPatternSalt(f *testing.F)      { fuzzHex(f, patternSalt) }

// fuzzDecimal: an accepted decimal re-formats to itself within bitSize bits.
func fuzzDecimal(f *testing.F, p *Pattern, bitSize int) {
	for _, seed := range []string{"0", "1", "007", "-1", "+1", "1e3", "18446744073709551615", "18446744073709551616", "9223372036854775808", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !p.Accepts(s) {
			return
		}
		v, err := strconv.ParseUint(s, 10, bitSize)
		if err != nil || strconv.FormatUint(v, 10) != s {
			t.Fatalf("%s accepted the non-canonical %q", p.Name, s)
		}
	})
}

func FuzzPatternSolution(f *testing.F) { fuzzDecimal(f, patternSolution, 64) }

// FuzzPatternSeqQuery: a page cursor's text either parses into an int64 that formats back to
// it, or parseQuery refuses it at the integer step.
func FuzzPatternSeqQuery(f *testing.F) {
	for _, seed := range []string{"0", "1", "01", "9223372036854775807", "9223372036854775808", "-0", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternSeqQuery.Accepts(s) {
			return
		}
		if v, ok := parseInteger(s); ok && strconv.FormatInt(v, 10) != s {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

// FuzzIntegerLiteral: a JSON integer the walk admits formats back to its literal.
func FuzzIntegerLiteral(f *testing.F) {
	for _, seed := range []string{"0", "-0", "1", "-1", "01", "1.0", "1e2", "9223372036854775807", "-9223372036854775808", "9223372036854775808"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if v, ok := parseInteger(s); ok && strconv.FormatInt(v, 10) != s {
			t.Fatalf("accepted the non-canonical %q", s)
		}
	})
}

// FuzzPatternPendingToken: an accepted pending token is empty or three non-empty base64url
// segments within the parser's bound (its signature is the handler's to verify).
func FuzzPatternPendingToken(f *testing.F) {
	for _, seed := range []string{examplePendingToken, "", "a.b", "a..c", "a.b.c.d", "a.b.c=", strings.Repeat("a", 1025)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !patternPendingToken.Accepts(s) || s == "" {
			return
		}
		parts := strings.Split(s, ".")
		if len(parts) != 3 || len(s) > patternPendingToken.MaxLen {
			t.Fatalf("accepted %q", s)
		}
		for _, part := range parts {
			if part == "" || !utils.IsBase64URL(part) {
				t.Fatalf("accepted %q", s)
			}
		}
	})
}

// FuzzGateLoginBody: whatever login body the gate admits binds to LoginRequest, whose key is
// canonical base64url of 32 bytes, and re-encodes to the same bytes; nothing panics.
func FuzzGateLoginBody(f *testing.F) {
	valid := `{"auth_key":"` + exampleString(f, patternKey32) + `"}`
	for _, seed := range []string{valid, valid + valid, `{"auth_key":null}`, "null", "", `{"auth_key":"x","auth_key":"y"}`, strings.Repeat("[", 4096)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		r := httptest.NewRequest(http.MethodPost, models.PathLogin, strings.NewReader(body))
		r.Header.Set(utils.HeaderContentType, jsonContentType)
		var in *Input
		Gate(func(w http.ResponseWriter, r *http.Request) { in, _ = InputOf(r) })(httptest.NewRecorder(), r)
		if in == nil {
			return
		}
		var req models.LoginRequest
		if err := in.Bind(&req); err != nil || !patternKey32.Accepts(req.AuthKey) {
			t.Fatalf("admitted %q", body)
		}
		raw, ok := utils.DecodeExact(req.AuthKey, identity.KeySize)
		if !ok || base64.RawURLEncoding.EncodeToString(raw) != req.AuthKey {
			t.Fatalf("admitted the non-canonical %q", body)
		}
	})
}
