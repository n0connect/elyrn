package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"elyrn/internal/chat"
)

func TestParseConversationRoute_Whitelist(t *testing.T) {
	const id = "3b241101-e2bb-4255-8caf-4136c566a962"
	const note = "8e7d6c5b-4a39-4281-9f0e-0d1c2b3a4958"
	ok := map[string][2]string{
		"/api/v2/conversations":                          {"", ""},
		"/api/v2/conversations/" + id:                    {"", ""},
		"/api/v2/conversations/" + id + "/messages":      {"messages", ""},
		"/api/v2/conversations/" + id + "/read":          {"read", ""},
		"/api/v2/conversations/" + id + "/members":       {"members", ""},
		"/api/v2/conversations/" + id + "/notes":         {"notes", ""},
		"/api/v2/conversations/" + id + "/notes/" + note: {"notes", note},
	}
	for path, want := range ok {
		route, valid := parseConversationRoute(path)
		item := ""
		if route.item != uuid.Nil {
			item = route.item.String()
		}
		if !valid || route.sub != want[0] || item != want[1] {
			t.Errorf("%s: valid=%v sub=%q item=%q", path, valid, route.sub, item)
		}
	}
	for _, path := range []string{
		"/api/v2/conversations/",
		"/api/v2/conversations/" + id + "/",
		"/api/v2/conversations/" + id + "/messages/x",
		"/api/v2/conversations/" + id + "/messages/" + note,
		"/api/v2/conversations/" + id + "/members/" + note,
		"/api/v2/conversations/" + id + "/notes/",
		"/api/v2/conversations/" + id + "/notes/x",
		"/api/v2/conversations/" + id + "/notes/" + note + "/x",
		"/api/v2/conversations/" + id + "/roster",
		"/api/v2/conversations/3B241101-E2BB-4255-8CAF-4136C566A962",   // non-canonical case
		"/api/v2/conversations/3b241101-e2bb-1255-8caf-4136c566a962",   // not v4
		"/api/v2/conversations/{3b241101-e2bb-4255-8caf-4136c566a962}", // braces
		"/api/v2/conversations/../me",
	} {
		if _, valid := parseConversationRoute(path); valid {
			t.Errorf("%s accepted", path)
		}
	}
}

func TestParsePageCursor_Whitelist(t *testing.T) {
	valid := map[string]chat.PageCursor{
		"":                           {Kind: chat.CursorLatest},
		"after=0":                    {Kind: chat.CursorAfter, Seq: 0},
		"after=42":                   {Kind: chat.CursorAfter, Seq: 42},
		"before=1":                   {Kind: chat.CursorBefore, Seq: 1},
		"before=9223372036854775807": {Kind: chat.CursorBefore, Seq: 9223372036854775807},
	}
	for query, want := range valid {
		r := httptest.NewRequest("GET", "/api/v2/conversations/x/messages?"+query, nil)
		if got, ok := parsePageCursor(r); !ok || got != want {
			t.Errorf("query %q: got %+v ok=%v, want %+v", query, got, ok, want)
		}
	}
	for _, query := range []string{
		"after=-1",
		"after=1e3",
		"after=",
		"after=+1",
		"after=1&after=2",
		"after=1&limit=5",
		"after=99999999999999999999",
		"before=0",
		"before=-1",
		"before=",
		"before=0x10",
		"before=1&before=2",
		"after=1&before=2",
		"before=9223372036854775808",
		"limit=5",
		"After=1",
	} {
		r := httptest.NewRequest("GET", "/api/v2/conversations/x/messages?"+query, nil)
		if _, ok := parsePageCursor(r); ok {
			t.Errorf("query %q accepted", query)
		}
	}
}
