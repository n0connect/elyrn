package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"elyrn/internal/apperr"
)

// The agent repeats nginx's edge ids (http.go edgeAnswers) because importing the server's
// registry would carry its store into the agent binary. The two tables must stay one: every id
// nginx answers is known to the agent under the same status, and the agent knows no other.
func TestEdgeAnswers_MatchTheServersRegistry(t *testing.T) {
	if len(edgeAnswers) != len(apperr.EdgeAnswers) {
		t.Fatalf("the agent knows %d edge ids, nginx answers %d", len(edgeAnswers), len(apperr.EdgeAnswers))
	}
	for _, served := range apperr.EdgeAnswers {
		known, ok := edgeAnswers[served.ID]
		if !ok || known.status != served.Status {
			t.Fatalf("edge id %s (status %d): the agent has %+v, %v", served.ID, served.Status, known, ok)
		}
	}
}

// The agent tells the server's two 409s of a send apart by the registered message of "Id taken"
// (serverIDTaken, repeated from apperr). Read from the server's own Write: "Id taken" is taken,
// "Conflict" (the earlier attempt is stored) and every other registered answer are not.
func TestIDTaken_MatchesTheServersRegistry(t *testing.T) {
	recognizesOnly(t, idTaken, apperr.IDTaken, serverIDTaken, http.StatusBadRequest)
}

// The agent tells the server's "Sender card mismatch" from the generic 400 by its registered
// message (serverSenderCardMismatch, repeated from apperr), read from the server's own Write.
func TestSenderCardMismatch_MatchesTheServersRegistry(t *testing.T) {
	recognizesOnly(t, senderCardMismatch, apperr.SenderCardMismatch, serverSenderCardMismatch, http.StatusConflict)
}

// recognizesOnly asserts that recognize, given every registered answer as the server writes it,
// holds for want's alone; never for no answer; and not for message (the agent's copy of want's
// sentence) under otherStatus.
func recognizesOnly(t *testing.T, recognize func(*answer) bool, want apperr.Code, message string, otherStatus int) {
	t.Helper()
	for code := apperr.MethodNotAllowed; code <= apperr.Internal; code++ {
		rec := httptest.NewRecorder()
		apperr.Write(rec, "test", code)
		got := recognize(&answer{status: rec.Code, body: rec.Body.Bytes()})
		if got != (code == want) {
			id, _ := apperr.Describe(code)
			t.Fatalf("%s: recognized = %v", id, got)
		}
	}
	if recognize(nil) {
		t.Fatal("no answer was recognized")
	}
	if recognize(&answer{status: otherStatus, body: []byte(`{"message":"` + message + `"}`)}) {
		t.Fatalf("the message under status %d was recognized", otherStatus)
	}
}
