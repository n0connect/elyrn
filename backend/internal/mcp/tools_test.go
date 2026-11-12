package mcp

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"elyrn/internal/agent"
)

const validRoom = `"0b6b9a54-3c0e-4f3a-9d6c-2a1f0e5b7c11"`

// callError runs tools/call on a server without a backend: every case below must be refused by
// validation before a backend method is reached, and answered as a tool error with its code.
func callError(t *testing.T, name ToolName, args string) agent.Code {
	t.Helper()
	params, err := json.Marshal(map[string]json.RawMessage{"name": json.RawMessage(`"` + string(name) + `"`), "arguments": json.RawMessage(args)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := &Server{}
	got, err := s.callTool(context.Background(), params)
	if err != nil {
		t.Fatalf("%s %s: protocol error %v, want a tool error", name, args, err)
	}
	result, ok := got.(toolResult)
	if !ok || !result.IsError || len(result.Content) != 1 || result.Content[0].Type != contentTypeText {
		t.Fatalf("%s %s: result %+v", name, args, got)
	}
	var body toolErrorBody
	if err := json.Unmarshal([]byte(result.Content[0].Text), &body); err != nil || body.Error.Message != agent.Sentence(body.Error.Code) {
		t.Fatalf("%s %s: error body %q (%v)", name, args, result.Content[0].Text, err)
	}
	return body.Error.Code
}

func TestToolArguments_AreValidatedBeforeAnythingIsSent(t *testing.T) {
	long := strings.Repeat("x", agent.MaxMessageChars+1)
	cases := []struct {
		tool ToolName
		args string
		want agent.Code
	}{
		{ToolIdentity, `{"x":1}`, agent.CodeArgument},
		{ToolIdentity, `[]`, agent.CodeArgument},
		{ToolRooms, `"rooms"`, agent.CodeArgument},
		{ToolRoomCreate, `{}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":1,"ttl_hours":24}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":33,"ttl_hours":24}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":4,"ttl_hours":0}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":4,"ttl_hours":721}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":4.5,"ttl_hours":24}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":"4","ttl_hours":24}`, agent.CodeArgument},
		{ToolRoomCreate, `{"max_members":4,"ttl_hours":24,"name":"x"}`, agent.CodeArgument},
		{ToolRoomJoin, `{}`, agent.CodeArgument},
		{ToolRoomJoin, `{"code":""}`, agent.CodeArgument},
		{ToolRoomJoin, `{"code":"elyrn:abc"}`, agent.CodeRoomCode},
		{ToolRoomJoin, `{"code":"elyrn#a b"}`, agent.CodeRoomCode},
		{ToolRoomJoin, `{"code":"` + strings.Repeat("a", maxRoomCodeChars+1) + `"}`, agent.CodeArgument},
		{ToolRoomMembers, `{}`, agent.CodeArgument},
		{ToolRoomMembers, `{"room":"0B6B9A54-3C0E-4F3A-9D6C-2A1F0E5B7C11"}`, agent.CodeArgument},
		{ToolRoomMembers, `{"room":"0b6b9a54-3c0e-1f3a-9d6c-2a1f0e5b7c11"}`, agent.CodeArgument},
		{ToolRoomMembers, `{"room":7}`, agent.CodeArgument},
		{ToolRoomSend, `{"room":` + validRoom + `}`, agent.CodeArgument},
		{ToolRoomSend, `{"room":` + validRoom + `,"text":"   "}`, agent.CodeMessageText},
		{ToolRoomSend, `{"room":` + validRoom + `,"text":"` + long + `"}`, agent.CodeMessageText},
		{ToolRoomSend, `{"room":` + validRoom + `,"text":"bell\u0007"}`, agent.CodeMessageText},
		{ToolRoomSend, `{"room":` + validRoom + `,"text":"swap` + "\u202e" + `me"}`, agent.CodeMessageText},
		{ToolRoomRead, `{"room":` + validRoom + `,"after":-1}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"after":9007199254740992}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"after":1e3}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"before":0}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"before":-1}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"before":9007199254740992}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"before":2.5}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"before":"5"}`, agent.CodeArgument},
		{ToolRoomRead, `{"room":` + validRoom + `,"after":1,"before":5}`, agent.CodeArgument},
		{ToolRoomWait, `{"room":` + validRoom + `}`, agent.CodeArgument},
		{ToolRoomWait, `{"room":` + validRoom + `,"after":0,"timeout_seconds":0}`, agent.CodeArgument},
		{ToolRoomWait, `{"room":` + validRoom + `,"after":0,"timeout_seconds":301}`, agent.CodeArgument},
		{ToolRoomLeave, `{"room":null}`, agent.CodeArgument},
	}
	for _, tc := range cases {
		if got := callError(t, tc.tool, tc.args); got != tc.want {
			t.Errorf("%s %s: code %s, want %s", tc.tool, tc.args, got, tc.want)
		}
	}
}

func TestMessageText_IsNormalizedAsTheBrowserDoes(t *testing.T) {
	for in, want := range map[string]string{
		"  hello  ":         "hello",
		"a\r\nb\rc":         "a\nb\nc",
		"tab\tand\nnewline": "tab\tand\nnewline",
		strings.Repeat("ç", agent.MaxMessageChars): strings.Repeat("ç", agent.MaxMessageChars),
	} {
		got, err := agent.ValidateMessageText(in)
		if err != nil || got != want {
			t.Errorf("ValidateMessageText(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := agent.ValidateMessageText("\xff"); err == nil {
		t.Error("invalid UTF-8 was accepted")
	}
}

func TestSchemas_MatchTheArgumentStructs(t *testing.T) {
	seen := map[ToolName]bool{}
	for _, tl := range tools {
		if seen[tl.name] {
			t.Fatalf("tool %s is listed twice", tl.name)
		}
		seen[tl.name] = true
		var tags []string
		typ := reflect.TypeOf(tl.args()).Elem()
		for i := 0; i < typ.NumField(); i++ {
			tags = append(tags, typ.Field(i).Tag.Get("json"))
		}
		var props []string
		for name := range tl.schema.Properties {
			props = append(props, name)
		}
		slices.Sort(tags)
		slices.Sort(props)
		if !slices.Equal(tags, props) {
			t.Errorf("%s: argument struct %v, schema %v", tl.name, tags, props)
		}
		for _, required := range tl.schema.Required {
			if _, ok := tl.schema.Properties[required]; !ok {
				t.Errorf("%s: required %s is not a property", tl.name, required)
			}
		}
		if tl.schema.AdditionalProperties || tl.schema.Type != typeObject {
			t.Errorf("%s: the schema must be a closed object", tl.name)
		}
	}
}

// Design D7: every tool that returns room messages says their text is data.
func TestMessageTools_LabelReceivedTextAsData(t *testing.T) {
	for _, name := range []ToolName{ToolRoomRead, ToolRoomWait} {
		if tl := findTool(name); tl == nil || !strings.Contains(tl.description, dataNotInstructions) {
			t.Errorf("%s does not label message text as data", name)
		}
	}
}

// The schema advertises the same history cursor the validation enforces: seq 0 has no history.
func TestRoomRead_BeforeSchemaMatchesTheValidation(t *testing.T) {
	tl := findTool(ToolRoomRead)
	if tl == nil {
		t.Fatal("room_read is not listed")
	}
	p, ok := tl.schema.Properties[argBefore]
	if !ok || p.Minimum == nil || *p.Minimum != minBeforeSeq || p.Maximum == nil || *p.Maximum != maxSeqArg {
		t.Fatalf("room_read before property %+v", p)
	}
	if slices.Contains(tl.schema.Required, argBefore) {
		t.Fatal("before must stay optional")
	}
}
