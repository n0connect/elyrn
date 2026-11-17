package integration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"elyrn/internal/apperr"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// The server never opens a role: it stores whatever 93 bytes a client sealed. These tests use
// random bytes of that size, which is exactly what the server can check of a genuine one.
func newRole(t *testing.T) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, utils.RoomRoleBytes))
}

func (s *roomSide) setRole(card, role string) *httptest.ResponseRecorder {
	return s.u.do(http.MethodPost, s.path("/members"), models.SetRoleRequest{Card: card, Role: role})
}

// roleOf is the role the roster serves for card, and whether card is on it.
func roleOf(members []models.RoomMemberDTO, card string) (string, bool) {
	for _, m := range members {
		if m.Card == card {
			return m.Role, true
		}
	}
	return "", false
}

func expectRole(t *testing.T, viewer *roomSide, card, want, what string) {
	t.Helper()
	got, ok := roleOf(viewer.members(t), card)
	if !ok || got != want {
		t.Fatalf("%s: role %q (listed %v), want %q", what, got, ok, want)
	}
}

func TestRoles_OwnerSetsAnyRoleAMemberOnlyItsOwn(t *testing.T) {
	mux := setup(t)
	a, b, c := roomOfThree(t, mux)

	for _, card := range []string{a.member.Card, b.member.Card, c.member.Card} {
		expectRole(t, b, card, "", "a member that never had a role")
	}

	forBob := newRole(t)
	expectStatus(t, a.setRole(b.member.Card, forBob), http.StatusNoContent, "the owner sets bob's role")
	for _, viewer := range []*roomSide{a, b, c} {
		expectRole(t, viewer, b.member.Card, forBob, "bob's role as every member reads it")
	}
	own := newRole(t)
	expectStatus(t, b.setRole(b.member.Card, own), http.StatusNoContent, "bob sets his own role")
	expectRole(t, c, b.member.Card, own, "bob's own role")
	expectStatus(t, b.setRole(b.member.Card, own), http.StatusNoContent, "bob sets the same role again")
	ownerOwn := newRole(t)
	expectStatus(t, a.setRole(a.member.Card, ownerOwn), http.StatusNoContent, "the owner sets her own role")

	// A member who does not own the room cannot touch anyone else's role, the owner's included
	forCarol, forAlice := newRole(t), newRole(t)
	expectAnswer(t, b.setRole(c.member.Card, forCarol), apperr.RoleNotAllowed, "bob sets carol's role")
	expectAnswer(t, c.setRole(a.member.Card, forAlice), apperr.RoleNotAllowed, "carol sets the owner's role")
	expectRole(t, a, c.member.Card, "", "carol's role after a refused set")
	expectRole(t, a, a.member.Card, ownerOwn, "the owner's role after a refused set")

	// Only the size is checked: one byte short or long, or not base64url, is refused at the gate
	raw := randomBytes(t, utils.RoomRoleBytes+1)
	for name, bad := range map[string]string{
		"one byte short": base64.RawURLEncoding.EncodeToString(raw[:utils.RoomRoleBytes-1]),
		"one byte long":  base64.RawURLEncoding.EncodeToString(raw),
		"not base64url":  own[:len(own)-1] + "*",
		"empty":          "",
	} {
		expectStatus(t, b.setRole(b.member.Card, bad), http.StatusBadRequest, name)
	}
	expectRole(t, a, b.member.Card, own, "bob's role after refused malformed sets")
}

// Who may not set a role learns nothing: a card nobody in the room has, a non-member, a
// conversation that does not exist and a one-to-one conversation all answer like a missing one.
func TestRoles_RefusalsAnswerLikeAMissingConversation(t *testing.T) {
	mux := setup(t)
	alice, bob, dave := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	b := joinRoom(t, bob, a.code)
	pairID := pair(t, alice, bob)

	missing := alice.do(http.MethodPost, "/api/v2/conversations/"+uuid.NewString()+"/members",
		models.SetRoleRequest{Card: b.member.Card, Role: newRole(t)})
	expectAnswer(t, missing, apperr.NotFound, "a conversation that does not exist")

	outsider := sideOf(t, dave, a.code) // holds the code, never joined: a card that is in no roster
	expectSameAnswer(t, a.setRole(outsider.member.Card, newRole(t)), missing, "the owner sets a role for a card not in the room")
	expectSameAnswer(t, outsider.setRole(b.member.Card, newRole(t)), missing, "a non-member sets a member's role")
	expectSameAnswer(t, outsider.setRole(outsider.member.Card, newRole(t)), missing, "a non-member sets its own role")
	expectSameAnswer(t, alice.do(http.MethodPost, "/api/v2/conversations/"+pairID+"/members",
		models.SetRoleRequest{Card: b.member.Card, Role: newRole(t)}), missing, "a role in a one-to-one conversation")

	// A non-owner's own refusal (403) only comes after membership and the card were proved
	expectAnswer(t, b.setRole(a.member.Card, newRole(t)), apperr.RoleNotAllowed, "bob sets the owner's role")
	expectSameAnswer(t, b.setRole(outsider.member.Card, newRole(t)), missing, "bob sets a role for a card not in the room")

	var stored []models.ConversationMember
	database.DB.Where("conversation_id = ?", a.room.ID).Find(&stored)
	for _, m := range stored {
		if m.Role != "" {
			t.Fatal("a refused set stored a role")
		}
	}
}

// The role is a column of the membership: it goes when the member leaves, the room burns or the
// account is deleted, and a member who rejoins starts with none.
func TestRoles_GoWithTheMembership(t *testing.T) {
	mux := setup(t)
	a, b, c := roomOfThree(t, mux)
	alice, bob, carol := a.u, b.u, c.u
	expectStatus(t, a.setRole(b.member.Card, newRole(t)), http.StatusNoContent, "bob's role")
	expectStatus(t, a.setRole(c.member.Card, newRole(t)), http.StatusNoContent, "carol's role")

	expectStatus(t, bob.do(http.MethodDelete, b.path(""), nil), http.StatusNoContent, "bob leaves")
	if _, listed := roleOf(a.members(t), b.member.Card); listed {
		t.Fatal("bob is still on the roster")
	}
	joinRoom(t, bob, a.code)
	expectRole(t, a, b.member.Card, "", "bob's role after leaving and rejoining")

	expectStatus(t, carol.do(http.MethodDelete, "/api/v2/me", models.DeleteAccountRequest{AuthKey: carol.authKey}), http.StatusOK, "carol deletes her account")
	if _, listed := roleOf(a.members(t), c.member.Card); listed {
		t.Fatal("carol's membership and role survived her account")
	}

	expectStatus(t, alice.do(http.MethodDelete, a.path(""), nil), http.StatusNoContent, "the owner burns")
	var n int64
	database.DB.Model(&models.ConversationMember{}).Where("conversation_id = ?", a.room.ID).Count(&n)
	if n != 0 {
		t.Fatalf("%d memberships (with their roles) survived the burn", n)
	}
}

// A roster entry is exactly {"card","mine","owner","role"}: clients decode it strictly.
func TestRoles_RosterEntriesCarryExactlyTheirFields(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	joinRoom(t, bob, a.code)
	expectStatus(t, a.setRole(a.member.Card, newRole(t)), http.StatusNoContent, "the owner's role")
	rr := alice.do(http.MethodGet, a.path("/members"), nil)
	expectStatus(t, rr, http.StatusOK, "roster")
	var raw struct {
		Members []map[string]json.RawMessage `json:"members"`
	}
	decode(t, rr, &raw)
	want := []string{"card", "mine", "owner", "role"}
	for _, entry := range raw.Members {
		if len(entry) != len(want) {
			t.Fatalf("a roster entry has %d fields: %v", len(entry), entry)
		}
		for _, key := range want {
			if _, ok := entry[key]; !ok {
				t.Fatalf("a roster entry lacks %q: %v", key, entry)
			}
		}
	}
}

// A role change tells every member, the caller included (its other devices).
func TestRoles_EveryMemberIsTold(t *testing.T) {
	mux := setup(t)
	a, b := roomOfTwo(t, mux)
	alice, bob := a.u, b.u

	srv := eventServer(t, mux)
	_, aliceLines := openEvents(t, srv, alice.cookie)
	_, bobLines := openEvents(t, srv, bob.cookie)
	waitFor(t, aliceLines, "retry: 3000")
	waitFor(t, bobLines, "retry: 3000")

	expectStatus(t, b.setRole(b.member.Card, newRole(t)), http.StatusNoContent, "bob sets his own role")
	waitFor(t, aliceLines, "event: conv")
	waitFor(t, bobLines, "event: conv")
}
