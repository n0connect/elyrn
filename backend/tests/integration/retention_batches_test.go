package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/chat"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/internal/store"

	"github.com/google/uuid"
)

// copiesOfFirstMessage stores n more copies of conv's message seq 1 (its real ciphertext, fresh
// ids and seqs above it), so a test reaches a volume no request could send in its time.
func copiesOfFirstMessage(t *testing.T, conv uuid.UUID, n int) {
	t.Helper()
	err := database.DB.Exec("INSERT INTO messages (conversation_id, seq, id, sender_tag, ciphertext, expires_on) "+
		"SELECT conversation_id, seq + g, gen_random_uuid(), sender_tag, ciphertext, expires_on "+
		"FROM messages, generate_series(1, ?) AS g WHERE conversation_id = ? AND seq = 1", n, conv).Error
	if err != nil {
		t.Fatalf("copy the first message: %v", err)
	}
}

func storedMessages(t *testing.T, conv uuid.UUID) int64 {
	t.Helper()
	var n int64
	if err := database.DB.Model(&models.Message{}).Where("conversation_id = ?", conv).Count(&n).Error; err != nil {
		t.Fatalf("count messages: %v", err)
	}
	return n
}

func orphanQueued(t *testing.T, conv uuid.UUID) bool {
	t.Helper()
	var n int64
	if err := database.DB.Model(&models.OrphanedConversation{}).Where("id = ?", conv).Count(&n).Error; err != nil {
		t.Fatalf("count orphans: %v", err)
	}
	return n == 1
}

// D2: expired messages leave in bounded batches, each committed on its own, and what one cycle
// leaves the next one takes. On the old single DELETE one pass removed everything at once (or,
// past its statement timeout, nothing at all).
func TestRetention_ExpiredMessagesGoInBatchesAcrossCycles(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	id := uuid.MustParse(conv)
	copiesOfFirstMessage(t, id, store.RetentionStepRowsForTesting)
	database.DB.Model(&models.Message{}).Where("conversation_id = ?", id).UpdateColumn("expires_on", time.Now().UTC().Add(-2*24*time.Hour))

	purgeAt(t, time.Now())
	if left := storedMessages(t, id); left != 1 {
		t.Fatalf("one cycle left %d expired messages, want exactly the one past its bound", left)
	}
	purgeAt(t, time.Now())
	if left := storedMessages(t, id); left != 0 {
		t.Fatalf("the next cycle left %d expired messages", left)
	}
}

// D1: a burn ends access in its request whatever the conversation holds; the messages and parts
// stay on disk as an orphan nobody can reach, counted against the file store, and retention
// removes them oldest first in bounded batches across cycles. On the old code the burn deleted
// every row in the request (this test then finds no row right after it).
func TestBurn_EndsAccessAtOnceAndRetentionRemovesTheRows(t *testing.T) {
	mux := filesSetup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	id := uuid.MustParse(conv)
	send(t, alice, bob, conv, 1)
	file, data := uuid.NewString(), newFilePart(t)
	expectStatus(t, alice.uploadPart(conv, file, 0, data), http.StatusCreated, "a part to burn")
	copiesOfFirstMessage(t, id, store.RetentionStepRowsForTesting)

	expectStatus(t, alice.do(http.MethodDelete, models.PathConversations+"/"+conv, nil), http.StatusNoContent, "burn a long conversation")
	if storedMessages(t, id) != int64(store.RetentionStepRowsForTesting)+1 || storedParts(t, id) != 1 || !orphanQueued(t, id) {
		t.Fatal("the burn did not leave its rows to retention as an orphan")
	}
	// Nothing of the orphan answers: every read is "no such conversation", byte for byte
	for _, c := range []*client{alice.client, bob.client} {
		expectIdentical(t, c.readPart(conv, file, 0), missingAnswer(t, c), "a part of the burned conversation")
		expectIdentical(t, c.do(http.MethodGet, models.PathConversations+"/"+conv+"/messages", nil),
			c.do(http.MethodGet, models.PathConversations+"/"+uuid.NewString()+"/messages", nil), "the burned conversation's messages")
	}

	purgeAt(t, time.Now())
	if left := storedMessages(t, id); left != 1 || !orphanQueued(t, id) {
		t.Fatalf("one cycle left %d orphan messages (queued %v), want 1 and the orphan still queued", left, orphanQueued(t, id))
	}
	purgeAt(t, time.Now())
	if storedMessages(t, id) != 0 || storedParts(t, id) != 0 || orphanQueued(t, id) {
		t.Fatal("the orphan outlived the next cycle")
	}
}

// A3: a room burned by its owner (or by the owner's account deletion) leaves a tombstone, and its
// code never opens a room again: a create under the burned id answers exactly as a create under
// an id in use. The tombstone holds the id and the room's expiry only, and retention drops it
// once that expiry passed.
func TestRooms_BurnedRoomCodeNeverOpensARoomAgain(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	recreate := func(u *user, a *roomSide) *httptest.ResponseRecorder {
		t.Helper()
		req := sideOf(t, u, a.code).createRequest(t)
		req.PoW = u.freshPoW()
		return u.do(http.MethodPost, "/api/v2/rooms", req)
	}

	a := createRoom(t, alice, 4, 24)
	joinRoom(t, bob, a.code)
	inUse := recreate(bob, a)
	expectAnswer(t, inUse, apperr.Conflict, "a create under a room id in use")
	expectStatus(t, alice.do(http.MethodDelete, a.path(""), nil), http.StatusNoContent, "the owner burns the room")
	expectIdentical(t, recreate(bob, a), inUse, "bob re-creates the burned room from its code")
	var stone models.BurnedRoom
	if err := database.DB.Where("id = ?", a.room.ID).First(&stone).Error; err != nil {
		t.Fatalf("no tombstone for the burned room: %v", err)
	}
	if !stone.ExpiresAt.Equal(time.Unix(a.code.ExpiresAt(), 0)) {
		t.Fatalf("the tombstone keeps %v, want the room's own expiry", stone.ExpiresAt)
	}
	expectStatus(t, carol.do(http.MethodPost, "/api/v2/rooms/join", sideOf(t, carol, a.code).joinRequest(t)), http.StatusNotFound, "a join with the burned code")

	// The owner's account deletion burns its rooms the same way
	d := createRoom(t, carol, 4, 24)
	expectStatus(t, carol.do(http.MethodDelete, models.PathMe, models.DeleteAccountRequest{AuthKey: carol.authKey}), http.StatusOK, "carol deletes her account")
	expectAnswer(t, recreate(bob, d), apperr.Conflict, "bob re-creates the room of a deleted owner")

	// Once the room's own expiry passed, retention drops the tombstone
	purgeAt(t, time.Now())
	expectRows(t, &models.BurnedRoom{}, 2, "tombstones before their expiry")
	database.DB.Model(&models.BurnedRoom{}).Where("id = ?", a.room.ID).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	purgeAt(t, time.Now())
	expectRows(t, &models.BurnedRoom{}, 1, "tombstones after one room's expiry")
}

// D2: the healthcheck reads cycles that finished, not cycles that began: a retention mark that
// cannot be parsed fails every cycle, and no such cycle counts as alive.
func TestRetention_AnUnreadableMarkIsNeverAFinishedCycle(t *testing.T) {
	setup(t)
	done, cancel := context.WithCancel(context.Background())
	cancel() // RunRetention runs one cycle, then sees ctx ended
	svc := chat.NewService()

	svc.RunRetention(done)
	finished := chat.RetentionFinishedForTesting()
	database.DB.Model(&models.KeyCheck{}).Where("name = ?", "retention-clock").UpdateColumn("value", "not a time")
	svc.RunRetention(done)
	if chat.RetentionFinishedForTesting() != finished {
		t.Fatal("a cycle that failed on an unreadable mark counted as finished")
	}
	database.DB.Where("name = ?", "retention-clock").Delete(&models.KeyCheck{})
	svc.RunRetention(done)
	if chat.RetentionFinishedForTesting() <= finished {
		t.Fatal("a cycle that ran through did not count as finished")
	}
}
