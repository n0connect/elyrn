package agent

import (
	"testing"

	"elyrn/internal/e2e"
)

// sealedRole seals text for member index i of the fixture, as a code holder does.
func (fx *roomFixture) sealedRole(tb testing.TB, i int, text string) string {
	tb.Helper()
	blob, err := fx.keys.SealRole(fx.members[i].Card, text)
	if err != nil {
		tb.Fatalf("SealRole: %v", err)
	}
	return blob
}

func TestServedRole_OpensForItsCardOrIsNone(t *testing.T) {
	fx := newRoomFixture(t)
	st := fx.state()
	blob := fx.sealedRole(t, 1, "lider")
	if got := st.openRole(fx.members[1].Card, blob); got != "lider" {
		t.Fatalf("openRole = %q", got)
	}
	if got := st.openRole(fx.members[1].Card, fx.sealedRole(t, 1, "")); got != "" {
		t.Fatalf("the sealed empty role opened as %q", got)
	}
	for name, served := range map[string]struct{ card, blob string }{
		"never set":                    {fx.members[1].Card, ""},
		"sealed for another card":      {fx.members[2].Card, blob},
		"not base64url":                {fx.members[1].Card, "#lider"},
		"cut":                          {fx.members[1].Card, blob[:len(blob)-1]},
		"the card itself":              {fx.members[1].Card, fx.members[1].Card},
		"another room's code":          {fx.members[1].Card, newRoomFixture(t).sealedRole(t, 1, "lider")},
		"sealed for this agent's card": {fx.members[0].Card, blob},
	} {
		if got := st.openRole(served.card, served.blob); got != "" {
			t.Errorf("%s: shown as %q", name, got)
		}
	}
}

func TestRoleTarget_OneMemberOrNothing(t *testing.T) {
	st := &roomState{roster: []rosterEntry{
		{aura: e2e.Aura{Name: "self", Code: "aaaa"}, mine: true},
		{aura: e2e.Aura{Name: "twin-1", Code: "bbbb"}},
		{aura: e2e.Aura{Name: "twin-2", Code: "bbbb"}},
		{aura: e2e.Aura{Name: "other", Code: "cccc"}},
	}}
	for member, want := range map[string]string{"": "self", "aaaa": "self", "cccc": "other"} {
		if got, err := st.roleTarget(member); err != nil || got.aura.Name != want {
			t.Errorf("roleTarget(%q) = %+v, %v; want %s", member, got, err, want)
		}
	}
	for member, want := range map[string]Code{"bbbb": CodeRoleMemberAmbiguous, "dddd": CodeRoleMemberUnknown} {
		if _, err := st.roleTarget(member); CodeOf(err) != want {
			t.Errorf("roleTarget(%q): %v, want %s", member, err, want)
		}
	}
	// The target is the roster's own entry: a role stored for it shows at once
	got, err := st.roleTarget("cccc")
	if err != nil || got != &st.roster[3] {
		t.Fatalf("roleTarget returned a copy: %v", err)
	}
}

func TestValidateRoleText_HasTheAgentsCode(t *testing.T) {
	if got, err := ValidateRoleText("üye"); err != nil || got != "üye" {
		t.Fatalf("ValidateRoleText = %q, %v", got, err)
	}
	for _, bad := range []string{"owner", "#x", "a b", "\xff"} {
		if _, err := ValidateRoleText(bad); CodeOf(err) != CodeRoleText {
			t.Errorf("ValidateRoleText(%q): %v, want %s", bad, err, CodeRoleText)
		}
	}
}

// FuzzServedRole: whatever the server serves as a member's role, the agent shows either nothing or
// exactly the role a code holder sealed for that member's card.
func FuzzServedRole(f *testing.F) {
	fx := newRoomFixture(f)
	genuine := make([]string, len(fx.members))
	for i := range fx.members {
		genuine[i] = fx.sealedRole(f, i, "lider")
		f.Add(uint8(i), genuine[i])
		f.Add(uint8(i), genuine[(i+1)%len(fx.members)])
		f.Add(uint8(i), genuine[i][:len(genuine[i])/2])
	}
	f.Add(uint8(0), "")
	f.Add(uint8(0), fuzzExtraChars)
	st := fx.state()
	f.Fuzz(func(t *testing.T, which uint8, sealed string) {
		i := int(which) % len(fx.members)
		got := st.openRole(fx.members[i].Card, sealed)
		if got == "" {
			return
		}
		if sealed != genuine[i] || got != "lider" {
			t.Fatalf("a role served for member %d showed as %q", i, got)
		}
	})
}
