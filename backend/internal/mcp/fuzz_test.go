package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/e2e"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Fuzz targets over the MCP stdio surface: the line reader and JSON-RPC decoder (FuzzServe),
// every tool's argument validation (FuzzToolArguments) and the room code whitelist
// (FuzzRoomCodeArgument). The backend below checks what reaches it and refuses every call with
// a registered code, so no target ever contacts a server.
// Run one with: go test -tags test -run '^$' -fuzz '^FuzzServe$' -fuzztime 30s ./internal/mcp

// checkingBackend is the tools' backend for fuzzing: it fails the test when validation let an
// out-of-range argument through, counts the calls that reached it, and refuses each one.
type checkingBackend struct {
	t       *testing.T
	mu      sync.Mutex
	reached int
}

func (b *checkingBackend) refuse(valid bool, what string) error {
	if !valid {
		b.t.Errorf("the backend was reached with an invalid %s", what)
	}
	b.mu.Lock()
	b.reached++
	b.mu.Unlock()
	return agent.Fail(agent.CodeStopped, nil)
}

func (b *checkingBackend) calls() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.reached
}

func canonicalRoom(id uuid.UUID) bool {
	_, ok := utils.ParseCanonicalUUIDv4(id.String())
	return ok
}

func seqInRange(seq, minimum int64) bool { return seq >= minimum && seq <= maxSeqArg }

func (b *checkingBackend) Identity(context.Context) (*agent.IdentityResult, error) {
	return nil, b.refuse(true, "call")
}

func (b *checkingBackend) CreateRoom(_ context.Context, maxMembers, ttlHours int) (*agent.RoomCreated, error) {
	return nil, b.refuse(maxMembers >= agent.MinRoomMembers && maxMembers <= agent.MaxRoomMembers &&
		ttlHours >= agent.MinRoomTTLHours && ttlHours <= agent.MaxRoomTTLHours, "room size or lifetime")
}

func (b *checkingBackend) JoinRoom(_ context.Context, code string) (*agent.RoomJoined, error) {
	valid := code == strings.TrimSpace(code) && len(code) <= maxRoomCodeChars &&
		(strings.HasPrefix(code, e2e.RoomCodePrefix) || strings.HasPrefix(code, e2e.LegacyRoomCodePrefix))
	return nil, b.refuse(valid, "room code")
}

func (b *checkingBackend) Rooms(context.Context) (*agent.RoomsResult, error) {
	return nil, b.refuse(true, "call")
}

func (b *checkingBackend) Members(_ context.Context, id uuid.UUID) (*agent.MembersResult, error) {
	return nil, b.refuse(canonicalRoom(id), "room")
}

func (b *checkingBackend) SetRole(_ context.Context, id uuid.UUID, member, role string) (*agent.RoleSet, error) {
	again, err := agent.ValidateRoleText(role)
	valid := canonicalRoom(id) && err == nil && again == role && (member == "" || e2e.IsAuraCode(member))
	return nil, b.refuse(valid, "room, member or role")
}

func (b *checkingBackend) Send(_ context.Context, id uuid.UUID, text string) (*agent.Sent, error) {
	again, err := agent.ValidateMessageText(text)
	return nil, b.refuse(canonicalRoom(id) && err == nil && again == text, "room or text")
}

func (b *checkingBackend) Read(_ context.Context, id uuid.UUID, after *int64) (*agent.ReadResult, error) {
	return nil, b.refuse(canonicalRoom(id) && (after == nil || seqInRange(*after, 0)), "room or cursor")
}

func (b *checkingBackend) ReadBefore(_ context.Context, id uuid.UUID, before int64) (*agent.ReadResult, error) {
	return nil, b.refuse(canonicalRoom(id) && seqInRange(before, minBeforeSeq), "room or history cursor")
}

func (b *checkingBackend) Wait(_ context.Context, id uuid.UUID, after int64, timeout time.Duration) (*agent.ReadResult, error) {
	return nil, b.refuse(canonicalRoom(id) && seqInRange(after, 0) && timeout >= agent.MinWaitTimeout &&
		timeout <= agent.MaxWaitTimeout, "room, cursor or timeout")
}

func (b *checkingBackend) Leave(_ context.Context, id uuid.UUID) (*agent.Left, error) {
	return nil, b.refuse(canonicalRoom(id), "room")
}

// toolErrorCode decodes a tool error result and checks its sentence is the registered one.
func toolErrorCode(t *testing.T, result toolResult) agent.Code {
	t.Helper()
	if !result.IsError || len(result.Content) != 1 || result.Content[0].Type != contentTypeText {
		t.Fatalf("not one text tool error: %+v", result)
	}
	var body toolErrorBody
	decoder := json.NewDecoder(strings.NewReader(result.Content[0].Text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil || !agent.Registered(body.Error.Code) || body.Error.Message != agent.Sentence(body.Error.Code) {
		t.Fatalf("tool error body %q is not a registered code and its sentence (%v)", result.Content[0].Text, err)
	}
	return body.Error.Code
}

// checkAnswerLine asserts one stdout line is one JSON-RPC 2.0 answer and nothing else: a valid
// id, a result or an error, a registered code with its number and sentence.
func checkAnswerLine(t *testing.T, line []byte) {
	t.Helper()
	if len(line) > MaxLineBytes {
		t.Fatalf("an answer of %d bytes", len(line))
	}
	var a answer
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&a); err != nil || decoder.More() || a.JSONRPC != jsonrpcVersion {
		t.Fatalf("stdout carries %q, not one JSON-RPC answer (%v)", line, err)
	}
	if string(a.ID) != string(nullID) && !validID(a.ID) {
		t.Fatalf("an answer with the id %s", a.ID)
	}
	if (a.Error == nil) == (a.Result == nil) {
		t.Fatalf("an answer with both or neither of result and error: %q", line)
	}
	if a.Error != nil {
		code := a.Error.Data.Code
		number, ok := rpcNumbers[code]
		if !ok || a.Error.Code != number || a.Error.Message != agent.Sentence(code) {
			t.Fatalf("protocol error %+v is not a registered code with its number and sentence", a.Error)
		}
		return
	}
	var result toolResult
	if json.Unmarshal(a.Result, &result) == nil && result.IsError {
		toolErrorCode(t, result)
	}
}

func FuzzServe(f *testing.F) {
	for _, seed := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":"two","method":"tools/list"}` + "\n",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"room_send","arguments":{"room":` + validRoom + `,"text":"hi"}}}` + "\n" +
			`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"rooms"}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}` + "\n",
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"room_read","arguments":{"room":"x","after":-1}}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]` + "\n" + `not json` + "\n" + "\xff\xfe\n",
		`{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}` + "\r\n" + `{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}`,
		strings.Repeat("[", 1<<12) + strings.Repeat("]", 1<<12) + "\n",
		`{"jsonrpc":"2.0","id":9,"method":"ping","params":{"_meta":"` + strings.Repeat("x", MaxLineBytes) + `"}}` + "\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		backend := &checkingBackend{t: t}
		var out bytes.Buffer // written under the server's outLock only
		if err := Serve(context.Background(), bytes.NewReader(input), &out, backend); err != nil {
			t.Fatalf("Serve: %v", err)
		}
		written := out.Bytes()
		if len(written) == 0 {
			return
		}
		if written[len(written)-1] != '\n' {
			t.Fatal("stdout ends inside a line")
		}
		lines := bytes.Split(written[:len(written)-1], []byte("\n"))
		if len(lines) > bytes.Count(input, []byte("\n"))+1 {
			t.Fatalf("%d answers for at most %d lines", len(lines), bytes.Count(input, []byte("\n"))+1)
		}
		for _, line := range lines {
			checkAnswerLine(t, line)
		}
	})
}

func FuzzToolArguments(f *testing.F) {
	for i := range tools {
		for _, args := range []string{
			`{}`, `[]`, `null`, `"x"`, `{"x":1}`, `{"room":` + validRoom + `}`,
			`{"room":` + validRoom + `,"text":"hello","after":0,"before":1,"timeout_seconds":1}`,
			`{"max_members":2,"ttl_hours":1}`, `{"max_members":4.5,"ttl_hours":1e3}`, `{"code":"elyrn#AAAA"}`,
			`{"room":` + validRoom + `,"after":9007199254740991}`, `{"room":` + validRoom + `,"text":"\u202e"}`,
			`{}, "name":"rooms"`, `{"room":` + validRoom + `,"room":null}`,
			`{"room":` + validRoom + `,"role":"lider"}`, `{"room":` + validRoom + `,"role":"","member":"7f3a"}`,
			`{"room":` + validRoom + `,"role":"owner","member":"7F3A"}`, `{"room":` + validRoom + `,"role":"über","member":null}`,
			`{"room":` + validRoom + `,"role":"#x","member":"7f3a0"}`,
		} {
			f.Add(uint8(i), args)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, args string) {
		tl := tools[int(which)%len(tools)]
		params := json.RawMessage(`{"name":"` + string(tl.name) + `","arguments":` + args + `}`)
		backend := &checkingBackend{t: t}
		got, err := (&Server{backend: backend}).callTool(context.Background(), params)
		if err != nil {
			// arguments that are not one JSON value break the params themselves
			if code := agent.CodeOf(err); code != agent.CodeRPCParams && code != agent.CodeUnknownTool {
				t.Fatalf("protocol error %s for %s %s", code, tl.name, args)
			}
			return
		}
		result, ok := got.(toolResult)
		if !ok || !result.IsError {
			t.Fatalf("%s %s: a backend that refuses everything gave %+v", tl.name, args, got)
		}
		code := toolErrorCode(t, result)
		switch code {
		case agent.CodeStopped:
			if backend.calls() != 1 {
				t.Fatalf("%s %s: refused by a backend reached %d times", tl.name, args, backend.calls())
			}
			return
		case agent.CodeArgument, agent.CodeRoomCode, agent.CodeMessageText, agent.CodeRoleText:
			if backend.calls() != 0 {
				t.Fatalf("%s %s: refused as %s after reaching the backend", tl.name, args, code)
			}
		default:
			t.Fatalf("%s %s: code %s", tl.name, args, code)
		}
		// Refused by validation: the same call without any backend must give the same answer,
		// so nothing of the backend is touched before validation (5bef96f)
		bare, err := (&Server{}).callTool(context.Background(), params)
		if err != nil || !reflect.DeepEqual(bare, got) {
			t.Fatalf("%s %s: without a backend %+v, %v", tl.name, args, bare, err)
		}
	})
}

func FuzzRoomCodeArgument(f *testing.F) {
	code, err := e2e.NewRoomCode(e2e.MinRoomMembers, 1)
	if err != nil {
		f.Fatalf("NewRoomCode: %v", err)
	}
	canonical := code.String()
	legacy := e2e.LegacyRoomCodePrefix + strings.TrimPrefix(canonical, e2e.RoomCodePrefix)
	for _, seed := range []string{
		canonical, legacy, "  " + canonical + "\n", canonical + "A", canonical[:len(canonical)-1],
		strings.ToUpper(canonical), "elyrn:abc", "elyrn#a b", "elyrn#", "", strings.Repeat("a", maxRoomCodeChars+1),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		value, err := codeArg(&raw)
		parsed, parseErr := e2e.ParseRoomCode(strings.TrimSpace(raw)) // what JoinRoom parses
		if parseErr == nil && err != nil {
			t.Fatalf("the joinable code %q is refused as an argument", raw)
		}
		if err != nil {
			if code := agent.CodeOf(err); code != agent.CodeArgument && code != agent.CodeRoomCode {
				t.Fatalf("code %s for %q", code, raw)
			}
			return
		}
		if value != strings.TrimSpace(raw) || len(value) > maxRoomCodeChars {
			t.Fatalf("codeArg(%q) = %q", raw, value)
		}
		if parseErr != nil {
			return
		}
		again, err := e2e.ParseRoomCode(parsed.String())
		if err != nil || !bytes.Equal(again.Secret, parsed.Secret) || again.MaxMembers != parsed.MaxMembers || again.ExpiresHour != parsed.ExpiresHour {
			t.Fatalf("%q does not round-trip through its canonical form", raw)
		}
		if strings.HasPrefix(value, e2e.RoomCodePrefix) && parsed.String() != value {
			t.Fatalf("%q parsed although it is not canonical", value)
		}
	})
}

// FuzzRoleArguments: room_role reaches the backend exactly when the member is absent or of the
// shape the schema advertises (the same as e2e.IsAuraCode) and the role passes the role rule.
func FuzzRoleArguments(f *testing.F) {
	for _, seed := range []struct {
		role, member string
		withMember   bool
	}{
		{"lider", "", false}, {"", "7f3a", true}, {"owner", "7f3a", true}, {"Lider-1_x", "7F3A", true},
		{"über", "", true}, {"#x", "7f3a\n", true}, {"a b", "zzzz", true}, {"\xff", "7f3", true},
	} {
		f.Add(seed.role, seed.member, seed.withMember)
	}
	shape := regexp.MustCompile(memberCodePattern)
	f.Fuzz(func(t *testing.T, role, member string, withMember bool) {
		if shape.MatchString(member) != e2e.IsAuraCode(member) {
			t.Fatalf("the schema pattern and the validation disagree on %q", member)
		}
		args := map[string]any{argRoom: json.RawMessage(validRoom), argRole: role}
		if withMember {
			args[argMember] = member
		}
		raw, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var sent roleArgs // what the tool decodes (invalid UTF-8 arrives as U+FFFD)
		if err := json.Unmarshal(raw, &sent); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		_, roleErr := agent.ValidateRoleText(*sent.Role)
		reach := roleErr == nil && (sent.Member == nil || e2e.IsAuraCode(*sent.Member))
		backend := &checkingBackend{t: t}
		params := json.RawMessage(`{"name":"` + string(ToolRoomRole) + `","arguments":` + string(raw) + `}`)
		got, err := (&Server{backend: backend}).callTool(context.Background(), params)
		if err != nil {
			t.Fatalf("protocol error %v", err)
		}
		result, ok := got.(toolResult)
		if !ok || !result.IsError {
			t.Fatalf("a backend that refuses everything gave %+v", got)
		}
		code := toolErrorCode(t, result)
		if reach != (backend.calls() == 1) || (reach && code != agent.CodeStopped) ||
			(!reach && code != agent.CodeArgument && code != agent.CodeRoleText) {
			t.Fatalf("role %q member %q (%v): code %s after %d backend calls", role, member, withMember, code, backend.calls())
		}
	})
}
