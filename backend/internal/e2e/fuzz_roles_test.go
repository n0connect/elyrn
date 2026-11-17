package e2e

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Fuzz targets for member roles (role.go).
// Run one with: go test -tags test -run '^$' -fuzz '^FuzzOpenRoomRole$' -fuzztime 30s ./internal/e2e

// FuzzRoleText: what ValidateRoleText accepts is NFC, within both bounds, made of letters, digits,
// '-' and '_' only, not reserved, and accepted again unchanged; NFC-equal inputs get one answer.
func FuzzRoleText(f *testing.F) {
	for _, seed := range []string{"", "komutan", goRoleText, "über", "owner", "OwNeR", "you", "a b", "#x",
		strings.Repeat("𝒜", RoleMaxChars), strings.Repeat("a", RoleMaxChars+1), "\xff", "swap‮me", "ﬁ", "Ⅻ", "K"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, text string) {
		got, err := ValidateRoleText(text)
		if utf8.ValidString(text) {
			other, otherErr := ValidateRoleText(norm.NFD.String(text))
			if (err == nil) != (otherErr == nil) || other != got {
				t.Fatalf("%q and its NFD form are judged differently", text)
			}
		}
		if err != nil {
			return
		}
		if !norm.NFC.IsNormalString(got) || utf8.RuneCountInString(got) > RoleMaxChars || len(got) > RoleMaxBytes {
			t.Fatalf("ValidateRoleText(%q) = %q, out of the rule's bounds", text, got)
		}
		for _, r := range got {
			if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != roleHyphen && r != roleUnderscore {
				t.Fatalf("ValidateRoleText(%q) kept %U", text, r)
			}
		}
		for _, reserved := range reservedRoles {
			if strings.EqualFold(got, reserved) {
				t.Fatalf("ValidateRoleText(%q) accepted a reserved word", text)
			}
		}
		if again, err := ValidateRoleText(got); err != nil || again != got {
			t.Fatalf("ValidateRoleText is not idempotent on %q", got)
		}
	})
}

// FuzzOpenRoomRole: a served role opens only to what a code holder sealed for that very card
// (a fuzzer cannot forge AES-GCM), and what opens always passes the rule unchanged. Sealing any
// valid text and opening it gives the text back.
func FuzzOpenRoomRole(f *testing.F) {
	v := loadVectorRoom(f)
	for _, seed := range []string{goRoleBlob, goRoleClearBlob, goRoleBlob[:len(goRoleBlob)-1], goRoleBlob + "A", "", flip(f, goRoleBlob, 20)} {
		f.Add(seed, true, "lider")
		f.Add(seed, false, "owner")
	}
	f.Fuzz(func(t *testing.T, blob string, forB bool, text string) {
		card := browserCardA
		if forB {
			card = browserCardB
		}
		opened, err := v.room.OpenRole(card, blob)
		if err == nil {
			again, ruleErr := ValidateRoleText(opened)
			genuine := (blob == goRoleBlob && forB && opened == goRoleText) || (blob == goRoleClearBlob && !forB && opened == "")
			if ruleErr != nil || again != opened || !genuine {
				t.Fatalf("OpenRole(%q) = %q for a blob nobody sealed for this card", blob, opened)
			}
		}
		valid, ruleErr := ValidateRoleText(text)
		sealed, err := v.room.SealRole(card, text)
		if (err == nil) != (ruleErr == nil && valid == text) {
			t.Fatalf("SealRole(%q): %v, the rule says %v", text, err, ruleErr)
		}
		if err != nil {
			return
		}
		if got, err := v.room.OpenRole(card, sealed); err != nil || got != text {
			t.Fatalf("a sealed role %q opened as %q, %v", text, got, err)
		}
		other := browserCardB
		if forB {
			other = browserCardA
		}
		if _, err := v.room.OpenRole(other, sealed); err == nil {
			t.Fatal("a role opened for another member's card")
		}
	})
}
