package integration

import (
	"net/http"
	"strconv"
	"testing"

	"elyrn/internal/models"
)

// pagingLimit is a page size small enough that a handful of messages spans several pages.
const pagingLimit = 3

// messagesPage fetches one page of a conversation's messages and checks it is in ascending seq.
func messagesPage(t *testing.T, u *user, convID, query string) []int64 {
	t.Helper()
	path := "/api/v2/conversations/" + convID + "/messages"
	if query != "" {
		path += "?" + query
	}
	rr := u.do("GET", path, nil)
	expectStatus(t, rr, http.StatusOK, "page "+query)
	var page models.MessagesResponse
	decode(t, rr, &page)
	seqs := make([]int64, 0, len(page.Messages))
	for i, m := range page.Messages {
		if i > 0 && m.Seq <= seqs[i-1] {
			t.Fatalf("page %q is not in ascending seq: %d after %d", query, m.Seq, seqs[i-1])
		}
		seqs = append(seqs, m.Seq)
	}
	return seqs
}

func beforeQuery(seq int64) string { return "before=" + strconv.FormatInt(seq, 10) }

func expectSeqs(t *testing.T, got []int64, want []int64, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got seqs %v, want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s: got seqs %v, want %v", what, got, want)
		}
	}
}

// A pair pages back from the latest page to the first message, then gets an empty page.
func TestPaging_PairReachesTheBeginning(t *testing.T) {
	mux := setup(t)
	t.Setenv("MESSAGE_PAGE_LIMIT", strconv.Itoa(pagingLimit))
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	counters := map[*user]int64{}
	for i := 0; i < 7; i++ {
		from, to := alice, bob
		if i%2 == 1 {
			from, to = bob, alice
		}
		counters[from]++
		send(t, from, to, conv, counters[from])
	}

	expectSeqs(t, messagesPage(t, bob, conv, ""), []int64{5, 6, 7}, "latest page")
	expectSeqs(t, messagesPage(t, bob, conv, beforeQuery(5)), []int64{2, 3, 4}, "page before 5")
	expectSeqs(t, messagesPage(t, bob, conv, beforeQuery(2)), []int64{1}, "page before 2 (shorter: the beginning)")
	expectSeqs(t, messagesPage(t, bob, conv, beforeQuery(1)), []int64{}, "page before the first message")
	// A cursor above the last seq is the latest page; both sides read the same history
	expectSeqs(t, messagesPage(t, alice, conv, beforeQuery(1000)), []int64{5, 6, 7}, "page before a future seq")

	expectStatus(t, bob.do("GET", "/api/v2/conversations/"+conv+"/messages?before=0", nil), http.StatusBadRequest, "before=0")
	expectStatus(t, bob.do("GET", "/api/v2/conversations/"+conv+"/messages?before=3&after=1", nil), http.StatusBadRequest, "before and after")
}

// A late joiner pages back to their join and no further; earlier members page to the start.
func TestPaging_RoomStopsAtTheJoin(t *testing.T) {
	mux := setup(t)
	t.Setenv("MESSAGE_PAGE_LIMIT", strconv.Itoa(pagingLimit))
	alice, bob := register(t, mux), register(t, mux)
	a := createRoom(t, alice, 4, 24)
	a.say(t, "before bob 1", 1)
	a.say(t, "before bob 2", 2)
	b := joinRoom(t, bob, a.code)
	for counter := int64(3); counter <= 7; counter++ {
		a.say(t, "after bob "+strconv.FormatInt(counter, 10), counter)
	}
	room := a.room.ID.String()

	expectSeqs(t, messagesPage(t, b.u, room, ""), []int64{5, 6, 7}, "bob's latest page")
	expectSeqs(t, messagesPage(t, b.u, room, beforeQuery(5)), []int64{3, 4}, "bob's page before 5 (shorter: his join)")
	expectSeqs(t, messagesPage(t, b.u, room, beforeQuery(3)), []int64{}, "bob asks for what was sent before he joined")
	expectSeqs(t, messagesPage(t, b.u, room, beforeQuery(2)), []int64{}, "bob asks for the first message")

	expectSeqs(t, messagesPage(t, alice, room, beforeQuery(5)), []int64{2, 3, 4}, "alice's page before 5")
	expectSeqs(t, messagesPage(t, alice, room, beforeQuery(2)), []int64{1}, "alice's first message")
}
