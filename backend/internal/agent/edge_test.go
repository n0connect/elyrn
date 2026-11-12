package agent

import (
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
