package integration

import (
	"bytes"
	"encoding/base64"
	"testing"

	"elyrn/internal/models"
)

// A1 for the agent: every room message it sends carries, in its header, the card the server stores
// for its seat, also after a restart (a restarted agent derives a card under a fresh nonce). The
// server of this release refuses any other card (Sender card mismatch); this test reads the stored
// blob as a member does, so it holds whether or not the server already enforces it.

// The sender card of a room blob: magic(4) version(1) card(60)
const (
	headerCardStart = 5
	headerCardEnd   = headerCardStart + 60
)

func roomHeaderCard(t *testing.T, blob string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(blob)
	if err != nil || len(raw) < headerCardEnd {
		t.Fatalf("a room blob of %d bytes (%v)", len(raw), err)
	}
	return raw[headerCardStart:headerCardEnd]
}

func TestAgent_SendsTheCardTheServerStoresForItsSeat(t *testing.T) {
	mux := setup(t)
	path := newIdentityPath(t.TempDir(), "robot")
	srv := clientServer(t, mux)
	robot, room, carol := agentWithRoom(t, mux, srv, path)
	agentSend(t, robot, room, "before the restart")
	robot.Close()
	restarted := newAgent(t, srv.URL, path)
	agentSend(t, restarted, room, "after the restart")

	var stored string
	for _, card := range carol.roster(t) {
		if card != carol.member.Card {
			stored = card
		}
	}
	want, err := base64.RawURLEncoding.DecodeString(stored)
	if err != nil {
		t.Fatalf("decode the stored card: %v", err)
	}
	rr := carol.u.do("GET", carol.path("/messages"), nil)
	var resp models.MessagesResponse
	decode(t, rr, &resp)
	if len(resp.Messages) != 2 {
		t.Fatalf("%d messages", len(resp.Messages))
	}
	for _, m := range resp.Messages {
		if !bytes.Equal(roomHeaderCard(t, m.Ciphertext), want) {
			t.Fatalf("message %d carries a card other than the robot's stored one", m.Seq)
		}
	}
}
