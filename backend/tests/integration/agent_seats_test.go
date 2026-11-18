package integration

import (
	"context"
	"net/http"
	"testing"

	"elyrn/internal/agent"
	"elyrn/internal/e2e"

	"github.com/google/uuid"
)

// A2 for the agent (room-roster/duplicate-member-key-card-shadows-member), through the real
// server: a code holder joins with a card carrying another member's key and stores a role on its
// own seat. The agent lists that key once, disputed, without a role, refuses to set its role, and
// says so; when the copied key is the agent's own, it says that plainly.

// impostorOf joins room as a fresh account whose card announces victim's key (any code holder can
// seal one), and stores a role on that seat.
func impostorOf(t *testing.T, mux http.Handler, code *e2e.RoomCode, victim []byte) *roomSide {
	t.Helper()
	side := sideOf(t, register(t, mux), code)
	forged, err := side.room.SealCardForTesting(victim)
	if err != nil {
		t.Fatalf("SealCardForTesting: %v", err)
	}
	side.member.Card = forged
	expectStatus(t, side.u.do(http.MethodPost, "/api/v2/rooms/join", side.joinRequest(t)), http.StatusCreated, "the impostor joins")
	role, err := side.room.SealRole(forged, "imposter")
	if err != nil {
		t.Fatalf("SealRole: %v", err)
	}
	expectStatus(t, side.setRole(forged, role), http.StatusNoContent, "the impostor sets its own role")
	return side
}

func membersOf(t *testing.T, robot *agent.Agent, room uuid.UUID) *agent.MembersResult {
	t.Helper()
	members, err := robot.Members(context.Background(), room)
	if err != nil {
		t.Fatalf("Members: %v", err)
	}
	return members
}

func TestAgent_AnotherMembersCopiedKeyIsDisputed(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	carolCode := auraCode(t, carol.member.Public)
	before := membersOf(t, robot, room)
	impostorOf(t, mux, carol.code, carol.member.Public)

	after := membersOf(t, robot, room)
	if len(after.Members) != 2 || after.SafetyNumber == before.SafetyNumber || len(after.Warnings) != 1 ||
		after.Warnings[0].Code != agent.CodeSeatDisputed {
		t.Fatalf("members with a copied key: %+v", after)
	}
	for _, m := range after.Members {
		if m.Code == carolCode && (!m.Disputed || m.Role != "") {
			t.Fatalf("carol is shown as %+v", m)
		}
		if m.Mine && m.Disputed {
			t.Fatal("the robot's own entry is disputed")
		}
	}
	if _, err := robot.SetRole(context.Background(), room, carolCode, "lider"); agent.CodeOf(err) != agent.CodeRoleMemberDisputed {
		t.Fatalf("a role for a disputed member: %v, want %s", err, agent.CodeRoleMemberDisputed)
	}
}

func TestAgent_ItsOwnCopiedKeyIsSaidPlainly(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	var own []byte
	for _, card := range carol.roster(t) {
		if card != carol.member.Card {
			public, err := carol.room.OpenCard(card)
			if err != nil {
				t.Fatalf("OpenCard: %v", err)
			}
			own = public
		}
	}
	impostorOf(t, mux, carol.code, own)
	after := membersOf(t, robot, room)
	if len(after.Warnings) != 1 || after.Warnings[0].Code != agent.CodeOwnSeatDisputed {
		t.Fatalf("warnings %+v", after.Warnings)
	}
	for _, m := range after.Members {
		if m.Mine && (!m.Disputed || !m.Owner) {
			t.Fatalf("the robot's own entry %+v: disputed, and still the owner", m)
		}
	}
	if _, err := robot.SetRole(context.Background(), room, "", "lider"); agent.CodeOf(err) != agent.CodeRoleMemberDisputed {
		t.Fatalf("its own role with a copied key: %v, want %s", err, agent.CodeRoleMemberDisputed)
	}
}
