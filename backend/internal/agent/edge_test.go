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
	for code := apperr.MethodNotAllowed; code <= apperr.Internal; code++ {
		rec := httptest.NewRecorder()
		apperr.Write(rec, "test", code)
		got := idTaken(&answer{status: rec.Code, body: rec.Body.Bytes()})
		if got != (code == apperr.IDTaken) {
			id, _ := apperr.Describe(code)
			t.Fatalf("%s: idTaken = %v", id, got)
		}
	}
	if idTaken(nil) {
		t.Fatal("no answer is not an id taken")
	}
	// The message under another status is not the send's 409
	if idTaken(&answer{status: http.StatusBadRequest, body: []byte(`{"message":"` + serverIDTaken + `"}`)}) {
		t.Fatal("a 400 with the message is not an id taken")
	}
}
