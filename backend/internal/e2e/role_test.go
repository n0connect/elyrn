package e2e

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"elyrn/internal/cryptoengine"
)

func TestRoleText_TheRule(t *testing.T) {
	nfd := "über" // "über" decomposed: sealed in NFC
	for in, want := range map[string]string{
		"":                                "",
		"komutan":                         "komutan",
		"Lider-1_a":                       "Lider-1_a",
		"çağrı":                           "çağrı",
		"командир":                        "командир",
		"指挥官":                             "指挥官",
		"٣٤":                              "٣٤", // Arabic-Indic digits are \p{N}
		nfd:                               "über",
		strings.Repeat("é", RoleMaxChars): strings.Repeat("é", RoleMaxChars),
		strings.Repeat("𝒜", RoleMaxChars): strings.Repeat("𝒜", RoleMaxChars), // 4 bytes each: exactly 64
		"owners":                          "owners",
		"you2":                            "you2",
	} {
		got, err := ValidateRoleText(in)
		if err != nil || got != want {
			t.Errorf("ValidateRoleText(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		strings.Repeat("a", RoleMaxChars+1), "#lider", "two words", "tab\there", "dot.ted", "emoji😀",
		"owner", "OWNER", "Owner", "you", "YOU", "yOu", "line\n", "\u0007", "zero‍width",
		"swap‮me", "\xff", "a\x00",
	} {
		if got, err := ValidateRoleText(bad); err == nil {
			t.Errorf("ValidateRoleText(%q) accepted %q", bad, got)
		}
	}
}

func TestRole_OpensOnlyForItsRoomAndMember(t *testing.T) {
	_, room := roomFixture(t, 4)
	_, other := roomFixture(t, 4)
	a, b := joinAs(t, room, accountA), joinAs(t, room, accountB)
	blob, err := room.SealRole(b.member.Card, "lider")
	if err != nil {
		t.Fatalf("SealRole: %v", err)
	}
	if len(blob) != base64.RawURLEncoding.EncodedLen(roleBlobSize) {
		t.Fatalf("a role blob of %d characters", len(blob))
	}
	if got, err := room.OpenRole(b.member.Card, blob); err != nil || got != "lider" {
		t.Fatalf("OpenRole: %q %v", got, err)
	}
	bInOther := joinAs(t, other, accountB)
	for name, open := range map[string]func() (string, error){
		"another member's card": func() (string, error) { return room.OpenRole(a.member.Card, blob) },
		"another room":          func() (string, error) { return other.OpenRole(bInOther.member.Card, blob) },
		"tampered":              func() (string, error) { return room.OpenRole(b.member.Card, flip(t, blob, 40)) },
		"truncated":             func() (string, error) { return room.OpenRole(b.member.Card, blob[:len(blob)-1]) },
		"extended":              func() (string, error) { return room.OpenRole(b.member.Card, blob+"A") },
		"not canonical":         func() (string, error) { return room.OpenRole(b.member.Card, blob+"\n") },
		"never set":             func() (string, error) { return room.OpenRole(b.member.Card, "") },
		"malformed card":        func() (string, error) { return room.OpenRole(b.member.Card[1:], blob) },
	} {
		if got, err := open(); err == nil {
			t.Errorf("%s: the role opened as %q", name, got)
		}
	}
}

// A cleared role is the sealed empty role: the same size as any other, so set and cleared look
// alike to the server.
func TestRole_ClearedIsSealedAndOfTheSameSize(t *testing.T) {
	_, room := roomFixture(t, 4)
	a := joinAs(t, room, accountA)
	cleared, err := room.SealRole(a.member.Card, "")
	if err != nil {
		t.Fatalf("SealRole(empty): %v", err)
	}
	set, _ := room.SealRole(a.member.Card, strings.Repeat("ş", RoleMaxChars))
	if len(cleared) != len(set) || cleared == "" {
		t.Fatalf("cleared %d characters, set %d", len(cleared), len(set))
	}
	if got, err := room.OpenRole(a.member.Card, cleared); err != nil || got != "" {
		t.Fatalf("OpenRole(cleared) = %q, %v", got, err)
	}
}

func TestRole_SealRefusesWhatTheRuleRefuses(t *testing.T) {
	_, room := roomFixture(t, 4)
	a := joinAs(t, room, accountA)
	for _, bad := range []string{"owner", "two words", "über", strings.Repeat("a", RoleMaxChars+1)} {
		if _, err := room.SealRole(a.member.Card, bad); err == nil {
			t.Errorf("SealRole sealed %q", bad)
		}
	}
	if _, err := room.SealRole(a.member.Card[:len(a.member.Card)-1], "lider"); err == nil {
		t.Error("SealRole sealed for a malformed card")
	}
}

// sealRolePlain seals any 65-byte plaintext as a genuine code holder could, to prove the opener
// checks what is inside the tag too.
func sealRolePlain(t *testing.T, room *Room, card string, plain []byte) string {
	t.Helper()
	nonce, err := cryptoengine.RandomBytes(cryptoengine.GCMNonceSize)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}
	rawCard, err := decodeExact(card, roomCardSize)
	if err != nil {
		t.Fatalf("decode card: %v", err)
	}
	sealed, err := cryptoengine.SealAES256GCM(room.roleKey, nonce, plain, room.roleAAD(rawCard))
	if err != nil {
		t.Fatalf("SealAES256GCM: %v", err)
	}
	return encode(concat(nonce, sealed))
}

func TestRole_OpenRefusesWhatACodeHolderMisSealed(t *testing.T) {
	_, room := roomFixture(t, 4)
	a := joinAs(t, room, accountA)
	withLength := func(length byte, text string) []byte {
		plain := make([]byte, rolePlainSize)
		plain[0] = length
		copy(plain[1:], text)
		return plain
	}
	dirtyPadding := rolePlain("lider")
	dirtyPadding[rolePlainSize-1] = 1
	for name, plain := range map[string][]byte{
		"length over 64":     withLength(RoleMaxBytes+1, "lider"),
		"length past text":   withLength(byte(len("lider")-1), "lider"),
		"padding not zero":   dirtyPadding,
		"reserved word":      rolePlain("Owner"),
		"not NFC":            rolePlain("über"),
		"forbidden rune":     rolePlain("a b"),
		"invalid UTF-8":      rolePlain("\xc3"),
		"too many runes":     rolePlain(strings.Repeat("a", RoleMaxChars+1)),
		"short plaintext":    rolePlain("lider")[:rolePlainSize-1],
		"control in text":    rolePlain("a\u0085"),
		"bidi control alone": rolePlain("⁦"),
	} {
		if got, err := room.OpenRole(a.member.Card, sealRolePlain(t, room, a.member.Card, plain)); err == nil {
			t.Errorf("%s: opened as %q", name, got)
		}
	}
	if got, err := room.OpenRole(a.member.Card, sealRolePlain(t, room, a.member.Card, rolePlain("lider"))); err != nil || got != "lider" {
		t.Fatalf("a well-formed plaintext did not open: %q %v", got, err)
	}
}

// Go → browser role vectors (vectors-go.json, handed to frontend/js/room-crypto.js): the browser
// vector room, B's and A's browser cards, fixed nonces. The browser must seal these exact bytes.
const (
	goRoleKey        = "xjMx9pc58vaftB45sTasFN4Jj5M1QtdbxC4mIWh8vRE"
	goRoleText       = "Kâşif-7_ü"
	goRoleNonce      = "YGFiY2RlZmdoaWpr" // bytes 0x60..0x6b
	goRoleBlob       = "YGFiY2RlZmdoaWprHNSB5aHOmktWWRO1hdgWMgX54i2DUa1374H_1Gic0MlIzRiVDxSWf9TdtYiC5mLsXsJQE7I0e-x7c7nLmtJQsqX-kZB5DKuaizsGS8eZ-TwU"
	goRoleClearNonce = "cHFyc3R1dnd4eXp7" // bytes 0x70..0x7b
	goRoleClearBlob  = "cHFyc3R1dnd4eXp7K8j8IGJ442sUVPHFPHappkIBuLR5WO1SXweejr83EIbFBXIwPJBle8p3do13NDQ0jEFUNSVYj_7GjyNsjOjTwVEeYSYIs4UW4fZhaZfDeF4X"
)

func TestRoleInterop_GoVectors(t *testing.T) {
	v := loadVectorRoom(t)
	if encode(v.room.roleKey) != goRoleKey {
		t.Fatalf("K_role = %s", encode(v.room.roleKey))
	}
	for _, tc := range []struct{ card, text, nonce, blob string }{
		{browserCardB, goRoleText, goRoleNonce, goRoleBlob},
		{browserCardA, "", goRoleClearNonce, goRoleClearBlob},
	} {
		got, err := v.room.sealRoleWithNonce(tc.card, tc.text, mustDecode(t, tc.nonce))
		if err != nil || got != tc.blob {
			t.Fatalf("sealRoleWithNonce(%q) = %s, %v", tc.text, got, err)
		}
		opened, err := v.room.OpenRole(tc.card, tc.blob)
		if err != nil || opened != tc.text {
			t.Fatalf("OpenRole(%q vector) = %q, %v", tc.text, opened, err)
		}
		if !bytes.HasPrefix(mustDecode(t, tc.blob), mustDecode(t, tc.nonce)) {
			t.Fatal("the vector blob does not start with its nonce")
		}
	}
}

// Browser → Go role vectors belong here: once frontend/js/room-crypto.js seals roles, the blobs it
// makes for the vector room (browserCardA, browserCardB) are pinned in this file and opened by a
// TestRoleInterop_OpensWhatTheBrowserSealed beside the test above.
