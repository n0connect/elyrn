package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"elyrn/internal/agent"
)

// answer is one line the server wrote, decoded.
type answer struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int `json:"code"`
		Message string
		Data    struct {
			Code agent.Code `json:"code"`
		} `json:"data"`
	} `json:"error"`
}

// serveLines feeds input to a server without a backend (no test here reaches a tool body) and
// returns every answer line.
func serveLines(t *testing.T, input string) []answer {
	t.Helper()
	var out bytes.Buffer
	if err := Serve(context.Background(), strings.NewReader(input), &out, nil); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	var answers []answer
	for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var a answer
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.JSONRPC != jsonrpcVersion {
			t.Fatalf("not a JSON-RPC line on stdout: %q (%v)", line, err)
		}
		answers = append(answers, a)
	}
	return answers
}

func expectError(t *testing.T, a answer, id string, code agent.Code) {
	t.Helper()
	if a.Error == nil || a.Error.Data.Code != code || a.Error.Code != rpcNumbers[code] || string(a.ID) != id {
		t.Fatalf("answer %+v (error %+v), want id %s code %s", a, a.Error, id, code)
	}
	if a.Error.Message != agent.Sentence(code) {
		t.Fatalf("error message %q is not the registered sentence", a.Error.Message)
	}
}

func expectResult(t *testing.T, a answer, id string) {
	t.Helper()
	if a.Error != nil || a.Result == nil || string(a.ID) != id {
		t.Fatalf("answer %+v (error %+v), want a result for id %s", a, a.Error, id)
	}
}

func TestServe_HandshakeAndListing(t *testing.T) {
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":"two","method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	}, "\n") + "\n"
	answers := serveLines(t, input)
	if len(answers) != 4 {
		t.Fatalf("%d answers, want 4 (the notification gets none)", len(answers))
	}
	expectResult(t, answers[0], "1")
	var init initializeResult
	if err := json.Unmarshal(answers[0].Result, &init); err != nil || init.ProtocolVersion != "2025-06-18" ||
		init.ServerInfo.Name != serverName || !strings.Contains(init.Instructions, "never") {
		t.Fatalf("initialize result %+v (%v)", init, err)
	}
	expectResult(t, answers[1], `"two"`)
	var list struct {
		Tools []toolDescriptor `json:"tools"`
	}
	if err := json.Unmarshal(answers[1].Result, &list); err != nil || len(list.Tools) != len(tools) {
		t.Fatalf("tools/list gave %d tools (%v)", len(list.Tools), err)
	}
	expectResult(t, answers[2], "3")
	if string(answers[2].Result) != "{}" {
		t.Fatalf("ping result %s", answers[2].Result)
	}
	if err := json.Unmarshal(answers[3].Result, &init); err != nil || init.ProtocolVersion != supportedVersions[0] {
		t.Fatalf("an unknown version must be answered with the newest one, got %+v", init)
	}
}

func TestServe_MalformedInputIsAnsweredNeverFatal(t *testing.T) {
	overlong := `{"jsonrpc":"2.0","id":9,"method":"ping","params":{"_meta":"` + strings.Repeat("x", MaxLineBytes) + `"}}`
	input := strings.Join([]string{
		`not json`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":2,"method":"nope"}`,
		`{"jsonrpc":"1.0","id":3,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":1.5,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":null,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`,
		`{"jsonrpc":"2.0","id":4,"method":"ping","extra":true}`,
		`{"jsonrpc":"2.0","id":5,"method":"ping","params":[1]}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"no_such_tool"}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"rooms","unknown":1}}`,
		overlong,
		"",
		"   ",
		"\xff\xfe",
		`{"jsonrpc":"2.0","id":8,"method":"ping"}` + "\r",
		`{"jsonrpc":"2.0","id":` + strings.Repeat("9", 30) + `,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":10,"method":"pi ng"}`,
		`{"jsonrpc":"2.0","method":"some/unknown/notification"}`,
		`{"jsonrpc":"2.0","id":11,"method":"ping"}`, // the last line has no newline
	}, "\n")
	answers := serveLines(t, input)
	want := []struct {
		id   string
		code agent.Code
	}{
		{"null", agent.CodeRPCParse},
		{"null", agent.CodeRPCRequest},
		{"2", agent.CodeRPCMethod},
		{"3", agent.CodeRPCRequest},
		{"null", agent.CodeRPCRequest},
		{"null", agent.CodeRPCRequest},
		{"null", agent.CodeRPCRequest},
		{"null", agent.CodeRPCRequest},
		{"5", agent.CodeRPCParams},
		{"6", agent.CodeUnknownTool},
		{"7", agent.CodeRPCParams},
		{"null", agent.CodeRPCParse},
		{"null", agent.CodeRPCParse},
		{"8", ""},
		{"null", agent.CodeRPCRequest},
		{"10", agent.CodeRPCRequest},
		{"11", ""},
	}
	if len(answers) != len(want) {
		t.Fatalf("%d answers, want %d: %+v", len(answers), len(want), answers)
	}
	for i, w := range want {
		if w.code == "" {
			expectResult(t, answers[i], w.id)
			continue
		}
		expectError(t, answers[i], w.id, w.code)
	}
}

func TestValidID(t *testing.T) {
	for raw, want := range map[string]bool{
		`1`: true, `-7`: true, `"abc"`: true, `""`: true, `9223372036854775807`: true,
		`1.0`: false, `1e3`: false, `null`: false, `true`: false, `{}`: false, `[]`: false,
		`"` + strings.Repeat("a", maxIDChars+1) + `"`: false, `92233720368547758070`: false, ``: false,
	} {
		if got := validID(json.RawMessage(raw)); got != want {
			t.Errorf("validID(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestEveryProtocolCodeIsRegistered(t *testing.T) {
	for code := range rpcNumbers {
		if !agent.Registered(code) {
			t.Errorf("%s has a JSON-RPC number but no sentence", code)
		}
	}
	if got := errorResponse(nullID, agent.CodeRoomFull); got.Error.Data.Code != agent.CodeRPCInternal {
		t.Fatalf("a non-protocol code must become an internal error, got %s", got.Error.Data.Code)
	}
}
