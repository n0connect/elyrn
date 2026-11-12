package mcp

import (
	"encoding/json"
	"testing"
)

// The in-flight behaviour of Serve (ping during a wait, one call at a time, cancellation,
// stdin close) runs against a real agent and server in tests/integration/mcp_test.go.

func TestCanonicalID(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{`7`, `7`, true}, {`7`, `"7"`, false}, {`"a"`, `"a"`, true}, {`-1`, `-1`, true}, {`"x"`, `"y"`, false},
	} {
		if got := canonicalID(json.RawMessage(tc.a)) == canonicalID(json.RawMessage(tc.b)); got != tc.same {
			t.Errorf("canonicalID(%s) == canonicalID(%s) is %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
