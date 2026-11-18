package agent

import (
	"strings"
	"testing"

	"elyrn/internal/e2e"
	"elyrn/internal/models"
)

// A2 (room-roster/duplicate-member-key-card-shadows-member): a code holder can take a seat with a
// card carrying another member's key. The old roster kept the first card per key, so an impostor
// sorted first took that member's role and owner flag in this agent's view, and room_role wrote to
// the impostor's seat. Rows below are real cards of a real room; the impostor's card is sealed as
// any code holder can seal one (e2e SealCardForTesting).

// seatedState is the fixture's room as this agent holds it, with the code's seat limit.
func seatedState(fx *roomFixture) *roomState {
	st := fx.state()
	st.maxMembers = e2e.MaxRoomMembers
	return st
}

// impostorCard seals a fresh card announcing member i's key.
func (fx *roomFixture) impostorCard(tb testing.TB, i int) string {
	tb.Helper()
	card, err := fx.keys.SealCardForTesting(fx.members[i].Public)
	if err != nil {
		tb.Fatalf("SealCardForTesting: %v", err)
	}
	return card
}

// honestRows is the fixture's roster as served: this agent's seat flagged, member 1 the owner.
func (fx *roomFixture) honestRows() []models.RoomMemberDTO {
	return []models.RoomMemberDTO{
		{Card: fx.members[fuzzSelf].Card, Mine: true},
		{Card: fx.members[1].Card, Owner: true},
		{Card: fx.members[2].Card},
	}
}

func entryFor(t *testing.T, st *roomState, public []byte) *rosterEntry {
	t.Helper()
	var found *rosterEntry
	for i := range st.roster {
		if string(st.roster[i].public) == string(public) {
			if found != nil {
				t.Fatal("a key is listed twice")
			}
			found = &st.roster[i]
		}
	}
	if found == nil {
		t.Fatal("a key is not listed")
	}
	return found
}

func TestRoster_AnImpostorSeatDisputesTheKeyInsteadOfShadowingIt(t *testing.T) {
	fx := newRoomFixture(t)
	honest := seatedState(fx)
	if err := honest.verifyMembers(fx.honestRows()); err != nil {
		t.Fatalf("verifyMembers(honest): %v", err)
	}
	honestResult, err := honest.membersResult()
	if err != nil || len(honestResult.Warnings) != 0 {
		t.Fatalf("an honest room: %+v, %v", honestResult, err)
	}

	impostor := fx.impostorCard(t, 1)
	rows := append([]models.RoomMemberDTO{{Card: impostor, Role: fx.sealedRoleFor(t, impostor, "imposter")}}, fx.honestRows()...)
	st := seatedState(fx)
	if err := st.verifyMembers(rows); err != nil {
		t.Fatalf("verifyMembers(impostor first): %v", err)
	}
	victim := entryFor(t, st, fx.members[1].Public)
	if !victim.disputed() || victim.role != "" || !victim.owner || len(st.roster) != len(fx.members) || st.skipped != 0 {
		t.Fatalf("the impostor's seat shaped the victim's entry: %+v, skipped %d", victim, st.skipped)
	}
	if _, err := st.roleTarget(victim.aura.Code); CodeOf(err) != CodeRoleMemberDisputed {
		t.Fatalf("a role for a disputed member: %v, want %s", err, CodeRoleMemberDisputed)
	}
	result, err := st.membersResult()
	if err != nil {
		t.Fatalf("membersResult: %v", err)
	}
	if result.SafetyNumber == honestResult.SafetyNumber {
		t.Fatal("a room with a duplicated seat shows the honest room's safety number")
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != CodeSeatDisputed {
		t.Fatalf("warnings %+v", result.Warnings)
	}
	for _, m := range result.Members {
		if m.Code == victim.aura.Code && (!m.Disputed || m.Role != "" || !m.Owner) {
			t.Fatalf("room_members shows the victim as %+v", m)
		}
	}
}

// This agent's own key under a second, unflagged card: said plainly, its own role cannot be set.
func TestRoster_OwnKeyDisputedIsSaidPlainly(t *testing.T) {
	fx := newRoomFixture(t)
	st := seatedState(fx)
	rows := append(fx.honestRows(), models.RoomMemberDTO{Card: fx.impostorCard(t, fuzzSelf)})
	if err := st.verifyMembers(rows); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	result, err := st.membersResult()
	if err != nil || len(result.Warnings) != 1 || result.Warnings[0].Code != CodeOwnSeatDisputed ||
		result.Warnings[0].Message != Sentence(CodeOwnSeatDisputed) {
		t.Fatalf("own key disputed: %+v, %v", result, err)
	}
	if _, err := st.roleTarget(""); CodeOf(err) != CodeRoleMemberDisputed {
		t.Fatalf("own role with a disputed key: %v", err)
	}
}

// A card that does not open counts as a seat for the safety number, as in the browser.
func TestRoster_ACardThatDoesNotOpenChangesTheSafetyNumber(t *testing.T) {
	fx := newRoomFixture(t)
	honest, broken := seatedState(fx), seatedState(fx)
	if err := honest.verifyMembers(fx.honestRows()); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	garbage := strings.Repeat("A", len(fx.members[0].Card))
	if err := broken.verifyMembers(append(fx.honestRows(), models.RoomMemberDTO{Card: garbage})); err != nil {
		t.Fatalf("verifyMembers: %v", err)
	}
	a, errA := honest.membersResult()
	b, errB := broken.membersResult()
	if errA != nil || errB != nil || a.SafetyNumber == b.SafetyNumber || b.UnverifiedCards != 1 {
		t.Fatalf("honest %+v (%v), with a broken card %+v (%v)", a, errA, b, errB)
	}
}

func TestRoster_RefusesWhatTheServerMisattributes(t *testing.T) {
	fx := newRoomFixture(t)
	twoMine := fx.honestRows()
	twoMine = append(twoMine, models.RoomMemberDTO{Card: fx.impostorCard(t, fuzzSelf), Mine: true})
	otherMine := fx.honestRows()
	otherMine[1].Mine = true
	noneMine := fx.honestRows()
	noneMine[0].Mine = false
	for name, rows := range map[string][]models.RoomMemberDTO{
		"two seats flagged ours": twoMine, "another key flagged ours": otherMine, "our seat not flagged": noneMine, "empty": nil,
	} {
		if err := seatedState(fx).verifyMembers(rows); CodeOf(err) != CodeRoster {
			t.Errorf("%s: %v, want %s", name, err, CodeRoster)
		}
	}
}

// sealedRoleFor seals a role for any served card.
func (fx *roomFixture) sealedRoleFor(tb testing.TB, card, text string) string {
	tb.Helper()
	blob, err := fx.keys.SealRole(card, text)
	if err != nil {
		tb.Fatalf("SealRole: %v", err)
	}
	return blob
}
