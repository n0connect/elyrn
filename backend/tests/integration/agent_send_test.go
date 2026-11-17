package integration

// The agent's send against the real server's two 409s. A 409 "Conflict" after a lost answer is
// the agent's own earlier attempt, stored; a 409 "Id taken" is an id held by something else, so
// nothing was stored: the agent sends again under a fresh id (once), and never reports the
// refused attempt as stored. The hostile server below only loses an answer or rewrites a send's
// id to one the real server already holds; every answer the agent reads is the real server's.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"elyrn/internal/agent"
	"elyrn/internal/models"
)

// isMessageSend reports whether r posts a message to a conversation.
func isMessageSend(r *http.Request) bool {
	return r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, models.PathConversations+"/") &&
		strings.HasSuffix(r.URL.Path, "/"+models.SubMessages)
}

// withMessageID rewrites the id of the send r carries to id (the ciphertext stays the agent's).
func withMessageID(t *testing.T, r *http.Request, id string) {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("read the send: %v", err)
		return
	}
	var req models.SendMessageRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Errorf("decode the send: %v", err)
		return
	}
	req.ID = id
	if raw, err = json.Marshal(req); err != nil {
		t.Errorf("encode the send: %v", err)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.ContentLength = int64(len(raw))
}

// takenIDServer rewrites the id of the first `times` sends once taken is set, then serves sends
// unchanged; rewritten counts every send after taken was set.
func takenIDServer(t *testing.T, mux http.Handler, taken *atomic.Pointer[string], times int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var rewritten atomic.Int32
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if id := taken.Load(); id != nil && isMessageSend(r) && rewritten.Add(1) <= times {
			withMessageID(t, r, *id)
		}
		return false
	})
	return srv, &rewritten
}

// browserMessage stores one message from the browser user and hands its id to taken.
func browserMessage(t *testing.T, s *roomSide, taken *atomic.Pointer[string]) string {
	t.Helper()
	id := newMessageID()
	expectStatus(t, s.post(id, s.sealTo(t, s.roster(t), id, "the browser's", 1)), http.StatusCreated, "browser send")
	taken.Store(&id)
	return id
}

func TestAgentSend_ALostAnswerThenConflictIsStored(t *testing.T) {
	mux := setup(t)
	var dropped atomic.Bool
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if !isMessageSend(r) || !dropped.CompareAndSwap(false, true) {
			return false
		}
		return loseAnswer(t, mux, w, r)
	})
	robot, room, s := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	sent, err := robot.Send(context.Background(), room, "once")
	if err != nil || !dropped.Load() || !sent.Stored || sent.Seq != nil {
		t.Fatalf("Send after a lost answer = %+v, %v (want stored, seq unknown)", sent, err)
	}
	if got := s.read(t); len(got) != 1 || got[0].text != "once" {
		t.Fatalf("the room holds %+v, want the one message once", got)
	}
}

func TestAgentSend_AnIDTakenIsSentAgainUnderAFreshID(t *testing.T) {
	mux := setup(t)
	var taken atomic.Pointer[string]
	srv, rewritten := takenIDServer(t, mux, &taken, 1)
	robot, room, s := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	id := browserMessage(t, s, &taken)
	seq := agentSend(t, robot, room, "under a fresh id")
	if rewritten.Load() != 2 {
		t.Fatalf("%d sends reached the server, want the taken one and one more", rewritten.Load())
	}
	stored := messagesOf(t, s.u, room.String())
	if len(stored) != 2 || stored[0].ID != id || stored[1].ID == id || stored[1].Seq != seq {
		t.Fatalf("stored %+v, want the browser's message and the agent's under a fresh id at seq %d", stored, seq)
	}
	if got := s.read(t); got[0].text != "the browser's" || got[1].text != "under a fresh id" {
		t.Fatalf("the room reads %+v", got)
	}
}

func TestAgentSend_AnIDTakenTwiceIsNeverStored(t *testing.T) {
	mux := setup(t)
	var taken atomic.Pointer[string]
	srv, rewritten := takenIDServer(t, mux, &taken, 2)
	robot, room, s := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	id := browserMessage(t, s, &taken)
	sent, err := robot.Send(context.Background(), room, "never stored")
	if sent != nil || agent.CodeOf(err) != agent.CodeMessageIDTaken {
		t.Fatalf("Send under taken ids = %+v, %v (want %s)", sent, err, agent.CodeMessageIDTaken)
	}
	if rewritten.Load() != 2 {
		t.Fatalf("%d sends reached the server, want exactly the two refused ones", rewritten.Load())
	}
	if stored := messagesOf(t, s.u, room.String()); len(stored) != 1 || stored[0].ID != id {
		t.Fatalf("stored %+v, want only the browser's message", stored)
	}
}
