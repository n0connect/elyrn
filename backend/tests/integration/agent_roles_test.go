package integration

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"elyrn/internal/agent"
	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// Member roles as the robot sees them, through the real server: the robot seals roles a browser
// member opens, opens the roles members seal, and shows a role that does not open as none.

// rolesOf is each verified member's role by code, as the robot lists them.
func rolesOf(t *testing.T, robot *agent.Agent, room uuid.UUID) map[string]string {
	t.Helper()
	members, err := robot.Members(context.Background(), room)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	roles := make(map[string]string, len(members.Members))
	for _, m := range members.Members {
		roles[m.Code] = m.Role
	}
	return roles
}

func auraCode(t *testing.T, public []byte) string {
	t.Helper()
	aura, err := e2e.AuraOf(public)
	if err != nil {
		t.Fatalf("AuraOf: %v", err)
	}
	return aura.Code
}

// servedRole is the role the server serves for card, opened as a browser member opens it.
func servedRole(t *testing.T, viewer *roomSide, card string) (string, error) {
	t.Helper()
	sealed, ok := roleOf(viewer.members(t), card)
	if !ok || sealed == "" {
		t.Fatalf("no role stored for the card (listed %v)", ok)
	}
	return viewer.room.OpenRole(card, sealed)
}

// unusedCode is an aura code no member of the room has.
func unusedCode(roles map[string]string) string {
	for _, code := range []string{"0000", "0001", "0002"} {
		if _, taken := roles[code]; !taken {
			return code
		}
	}
	return "0003"
}

func TestAgent_RolesThroughTheRealServer(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	ctx := context.Background()
	carolCode := auraCode(t, carol.member.Public)
	robotCard := ""
	for _, card := range carol.roster(t) {
		if card != carol.member.Card {
			robotCard = card
		}
	}
	for code, role := range rolesOf(t, robot, room) {
		if role != "" {
			t.Fatalf("member %s has the role %q before anyone set one", code, role)
		}
	}

	own, err := robot.SetRole(ctx, room, "", "lider")
	if err != nil || own.Role != "lider" || own.Room != room.String() || own.Code == carolCode {
		t.Fatalf("SetRole(own) = %+v, %v", own, err)
	}
	if got, err := servedRole(t, carol, robotCard); err != nil || got != "lider" {
		t.Fatalf("carol opened the robot's role as %q, %v", got, err)
	}
	// The owner sets carol's role; typed decomposed, it is sealed in NFC
	theirs, err := robot.SetRole(ctx, room, carolCode, "üye")
	if err != nil || theirs.Role != "üye" || theirs.Code != carolCode {
		t.Fatalf("SetRole(carol) = %+v, %v", theirs, err)
	}
	if got, err := servedRole(t, carol, carol.member.Card); err != nil || got != "üye" {
		t.Fatalf("carol opened her role as %q, %v", got, err)
	}
	if roles := rolesOf(t, robot, room); roles[own.Code] != "lider" || roles[carolCode] != "üye" {
		t.Fatalf("roles listed %v", roles)
	}

	// Carol's own seal opens; a blob the server cannot tell from a role, or carol's role sealed
	// for the robot's card and stored as hers (a moved role), is shown as none
	sealed, err := carol.room.SealRole(carol.member.Card, "gözcü")
	if err != nil {
		t.Fatalf("SealRole: %v", err)
	}
	expectStatus(t, carol.setRole(carol.member.Card, sealed), http.StatusNoContent, "carol sets her own role")
	if roles := rolesOf(t, robot, room); roles[carolCode] != "gözcü" {
		t.Fatalf("the robot read carol's role as %q", roles[carolCode])
	}
	moved, err := carol.room.SealRole(robotCard, "gözcü")
	if err != nil {
		t.Fatalf("SealRole: %v", err)
	}
	for what, blob := range map[string]string{"random bytes": newRole(t), "a role sealed for another card": moved} {
		expectStatus(t, carol.setRole(carol.member.Card, blob), http.StatusNoContent, what)
		if roles := rolesOf(t, robot, room); roles[carolCode] != "" || roles[own.Code] != "lider" {
			t.Fatalf("%s: roles listed %v", what, roles)
		}
	}

	cleared, err := robot.SetRole(ctx, room, "", "")
	if err != nil || cleared.Role != "" {
		t.Fatalf("SetRole(clear) = %+v, %v", cleared, err)
	}
	if got, err := servedRole(t, carol, robotCard); err != nil || got != "" {
		t.Fatalf("a cleared role opened as %q, %v (it must be the sealed empty role)", got, err)
	}
	for _, refused := range []struct {
		member, role string
		want         agent.Code
	}{
		{"", "owner", agent.CodeRoleText},
		{"", "#lider", agent.CodeRoleText},
		{unusedCode(rolesOf(t, robot, room)), "lider", agent.CodeRoleMemberUnknown},
		{"7F3A", "lider", agent.CodeArgument},
	} {
		if _, err := robot.SetRole(ctx, room, refused.member, refused.role); agent.CodeOf(err) != refused.want {
			t.Fatalf("SetRole(%q, %q): %v, want %s", refused.member, refused.role, err, refused.want)
		}
	}
}

// A robot that does not own the room sets its own role only: the server's 403 has its own code.
func TestAgent_ANonOwnerSetsOnlyItsOwnRole(t *testing.T) {
	mux := setup(t)
	carol := createRoom(t, register(t, mux), situationMembers, situationTTLHours)
	robot := newAgent(t, clientServer(t, mux).URL, newIdentityPath(t.TempDir(), "robot"))
	ctx := context.Background()
	joined, err := robot.JoinRoom(ctx, carol.code.String())
	if err != nil {
		t.Fatalf("JoinRoom: %v", err)
	}
	room := uuid.MustParse(joined.Room)
	if _, err := robot.SetRole(ctx, room, auraCode(t, carol.member.Public), "lider"); agent.CodeOf(err) != agent.CodeRoleNotAllowed {
		t.Fatalf("a member set the owner's role: %v, want %s", err, agent.CodeRoleNotAllowed)
	}
	if own, err := robot.SetRole(ctx, room, "", "gözcü"); err != nil || own.Role != "gözcü" {
		t.Fatalf("SetRole(own) = %+v, %v", own, err)
	}
}

// The member leaves between the roster the robot read and its POST: the server's 404 is told as
// a member gone, not as a room this agent is no longer in.
func TestAgent_ARoleForAMemberWhoJustLeft(t *testing.T) {
	mux := setup(t)
	var carol atomic.Pointer[roomSide]
	var left atomic.Bool
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		side := carol.Load()
		if side != nil && r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/"+models.SubMembers) && !left.Swap(true) {
			if rr := side.u.do(http.MethodDelete, side.path(""), nil); rr.Code != http.StatusNoContent {
				t.Errorf("carol leaves: status %d", rr.Code) // the handler's goroutine may not end the test
			}
		}
		return false
	})
	robot, room, side := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	carol.Store(side)
	if _, err := robot.SetRole(context.Background(), room, auraCode(t, side.member.Public), "lider"); agent.CodeOf(err) != agent.CodeRoleMemberGone {
		t.Fatalf("a role for a member who left: %v, want %s", err, agent.CodeRoleMemberGone)
	}
}
