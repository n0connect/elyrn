package integration

// Negative use: every documented limit used against the system, exactly at it (admitted) and
// one over it (refused with its registered answer, consuming nothing but what the design says),
// and, where the configuration is read per request, lowered and raised again.
//
// What a refused over-limit request spends, from the code: the invite and the room handlers
// validate the request's shape, then spend the proof of work (pow.ValidateSolution), and only
// then does the chat service check the account's limits (MAX_ACTIVE_INVITES,
// MAX_CONVERSATIONS_PER_USER, ROOM_MAX_MEMBERS, the expiry window). So such a refusal spends its
// proof of work, which cannot be used again, and stores nothing else. Joins and redeems take no
// proof of work.

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/tests/testutil"
)

const (
	// limitInvites is the test configuration's MAX_ACTIVE_INVITES (testutil.SetupTestEnv)
	limitInvites = 5
	// limitConversations is the lowered MAX_CONVERSATIONS_PER_USER of the conversations test
	limitConversations = 2
	// limitPage is the lowered MESSAGE_PAGE_LIMIT of the paging test
	limitPage = 3
	// limitFrame is the padded frame of the ciphertexts of the message-size test; the limit is
	// set to exactly its ciphertext's size, then one byte below it
	limitFrame = 1024
	// limitRoomMembers is the lowered ROOM_MAX_MEMBERS of the room-size test
	limitRoomMembers = 3
	// streamReleaseAttempts bound the wait for a closed stream's slot to be released
	streamReleaseAttempts = 100
	streamReleasePause    = 20 * time.Millisecond
	// streamAccountsPerClient fill one network's share at the per-account cap
	streamAccountsPerClient = realtime.MaxSubscribersPerClient / realtime.MaxSubscribersPerMember
)

// pairCiphertextOfFrame is a well-formed one-to-one ciphertext whose padded frame is frame.
func pairCiphertextOfFrame(t *testing.T, frame int) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString(randomBytes(t, frame+pairOverhead))
}

// pairOverhead is the nonce and tag around a one-to-one frame
const pairOverhead = cryptoengine.GCMNonceSize + cryptoengine.GCMTagSize

func TestNegative_ActiveInvites(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	for i := 1; i <= limitInvites; i++ {
		expectStatus(t, alice.createInvite(), http.StatusCreated, "invite "+strconv.Itoa(i)+" of the limit")
	}
	over := models.CreateInviteRequest{PoW: alice.freshPoW()}
	expectAnswer(t, alice.do(http.MethodPost, models.PathInvites, over), apperr.LimitReached, "one invite over the limit")
	expectRows(t, &models.Invite{}, limitInvites, "one over the limit")
	// The design spends the proof of work before the limit check: it is gone
	expectAnswer(t, alice.do(http.MethodPost, models.PathInvites, over), apperr.PoWInvalid, "the refused request's proof of work again")

	t.Setenv("MAX_ACTIVE_INVITES", strconv.Itoa(limitInvites-2))
	expectAnswer(t, alice.createInvite(), apperr.LimitReached, "invites above a lowered limit")
	expectRows(t, &models.Invite{}, limitInvites, "a lowered limit keeps what exists")
	t.Setenv("MAX_ACTIVE_INVITES", strconv.Itoa(limitInvites+1))
	expectStatus(t, alice.createInvite(), http.StatusCreated, "the raised limit admits one more")
	expectRows(t, &models.Invite{}, limitInvites+1, "the raised limit")
}

func TestNegative_ConversationsPerUser(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	t.Setenv("MAX_CONVERSATIONS_PER_USER", strconv.Itoa(limitConversations))
	pair(t, alice, bob)
	createRoom(t, alice, 4, 24) // exactly at the limit
	carolsRoom := createRoom(t, carol, 4, 24)
	token := redeemToken(t, carol)
	before := countRows(t)

	expectAnswer(t, redeem(alice, token), apperr.LimitReached, "redeem over the limit")
	expectAnswer(t, alice.do(http.MethodPost, models.PathRoomsJoin, sideOf(t, alice, carolsRoom.code).joinRequest(t)),
		apperr.LimitReached, "join over the limit")
	create := sideOf(t, alice, newCode(t, 4, 24)).createRequest(t)
	create.PoW = alice.freshPoW()
	expectAnswer(t, alice.do(http.MethodPost, models.PathRooms, create), apperr.LimitReached, "create over the limit")
	expectRowsUnchanged(t, before, "requests over the conversation limit")
	expectAnswer(t, alice.do(http.MethodPost, models.PathRooms, create), apperr.PoWInvalid, "the refused create's proof of work again")
	if n := len(listOf(t, alice)); n != limitConversations {
		t.Fatalf("alice lists %d conversations, want %d", n, limitConversations)
	}

	t.Setenv("MAX_CONVERSATIONS_PER_USER", strconv.Itoa(limitConversations+1))
	expectStatus(t, alice.do(http.MethodPost, models.PathRoomsJoin, sideOf(t, alice, carolsRoom.code).joinRequest(t)),
		http.StatusCreated, "join under the raised limit")
	expectAnswer(t, redeem(alice, token), apperr.LimitReached, "redeem over the raised limit, now reached again")
}

func TestNegative_RoomMembers(t *testing.T) {
	mux := setup(t)
	alice, bob, carol := register(t, mux), register(t, mux), register(t, mux)
	a := createRoom(t, alice, 2, 24)
	joinRoom(t, bob, a.code) // exactly at the room's limit
	before := countRows(t)
	expectAnswer(t, carol.do(http.MethodPost, models.PathRoomsJoin, sideOf(t, carol, a.code).joinRequest(t)), apperr.RoomFull, "one over the room's limit")
	expectRowsUnchanged(t, before, "a join into a full room")

	shipped := config.GetRoomMaxMembers()
	t.Setenv("ROOM_MAX_MEMBERS", strconv.Itoa(limitRoomMembers))
	createRoom(t, alice, limitRoomMembers, 24) // exactly at the lowered setting
	over := sideOf(t, alice, newCode(t, limitRoomMembers+1, 24)).createRequest(t)
	over.PoW = alice.freshPoW()
	before = countRows(t)
	expectAnswer(t, alice.do(http.MethodPost, models.PathRooms, over), apperr.InvalidInput, "one over the lowered setting")
	expectRowsUnchanged(t, before, "a create over the setting")
	expectAnswer(t, alice.do(http.MethodPost, models.PathRooms, over), apperr.PoWInvalid, "the refused create's proof of work again")
	t.Setenv("ROOM_MAX_MEMBERS", strconv.Itoa(shipped))
	over.PoW = alice.freshPoW()
	expectStatus(t, alice.do(http.MethodPost, models.PathRooms, over), http.StatusCreated, "the same room under the raised setting")
}

func TestNegative_MessageBytes(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	path := models.PathConversations + "/" + conv + "/" + models.SubMessages
	shipped := config.GetMaxMessageBytes()
	exact := limitFrame + pairOverhead

	t.Setenv("MAX_MESSAGE_BYTES", strconv.Itoa(exact))
	expectStatus(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: newMessageID(), Ciphertext: pairCiphertextOfFrame(t, limitFrame)}),
		http.StatusCreated, "a ciphertext exactly at the limit")
	t.Setenv("MAX_MESSAGE_BYTES", strconv.Itoa(exact-1))
	id, over := newMessageID(), pairCiphertextOfFrame(t, limitFrame)
	expectAnswer(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: id, Ciphertext: over}), apperr.InvalidRequest, "one byte over the limit")
	expectRows(t, &models.Message{}, 1, "one byte over")
	if view := conversationView(t, bob, conv); view.LastSeq != 1 {
		t.Fatalf("a refused send moved last_seq to %d", view.LastSeq)
	}
	t.Setenv("MAX_MESSAGE_BYTES", strconv.Itoa(shipped))
	expectStatus(t, alice.do(http.MethodPost, path, models.SendMessageRequest{ID: id, Ciphertext: over}), http.StatusCreated, "the same message under the raised limit")
}

func TestNegative_PageLimit(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	t.Setenv("MESSAGE_PAGE_LIMIT", strconv.Itoa(limitPage))
	for i := int64(1); i <= limitPage+1; i++ {
		send(t, alice, bob, conv, i)
	}
	expectSeqs(t, messagesPage(t, bob, conv, ""), []int64{2, 3, 4}, "the latest page, one over the limit stored")
	expectSeqs(t, messagesPage(t, bob, conv, "after=0"), []int64{1, 2, 3}, "the first page")
	expectSeqs(t, messagesPage(t, bob, conv, "after=1"), []int64{2, 3, 4}, "exactly a page after the cursor")
	expectSeqs(t, messagesPage(t, bob, conv, beforeQuery(2)), []int64{1}, "the page before")
	t.Setenv("MESSAGE_PAGE_LIMIT", strconv.Itoa(limitPage+1))
	expectSeqs(t, messagesPage(t, bob, conv, ""), []int64{1, 2, 3, 4}, "the raised limit")
}

func TestNegative_NotesPerSenderAndAddressee(t *testing.T) {
	mux := setup(t)
	a, b := roomOfTwo(t, mux)
	firstID, first := a.note(t, b, "noaddx:first")
	expectStatus(t, a.postNote(firstID, b.member.Card, first), http.StatusCreated, "the one note that may wait")
	secondID, second := a.note(t, b, "noaddx:second")
	before := countRows(t)
	expectAnswer(t, a.postNote(secondID, b.member.Card, second), apperr.Conflict, "a second note while one waits")
	expectRowsUnchanged(t, before, "a second note")
	// The other direction is its own pair
	backID, back := b.note(t, a, "noaddx:back")
	expectStatus(t, b.postNote(backID, a.member.Card, back), http.StatusCreated, "bob's note to alice")
}

// streamServer serves mux over real HTTP with every request from addr (one client key).
func streamServer(t *testing.T, mux http.Handler, addr string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = addr
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// streamReady is the first line of an admitted event stream (handlers.EventsHandler's preamble)
const streamReady = "retry: 3000\n"

// dialStream opens /events for u through srv: an admitted stream (read up to its ready line)
// comes back with its closer and status 200; anything else is read in full and closed.
func dialStream(t *testing.T, srv *httptest.Server, u *user) (closer func(), resp *http.Response, body []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+models.PathEvents, nil)
	if err != nil {
		cancel()
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(u.cookie)
	resp, err = srv.Client().Do(req)
	if err != nil {
		cancel()
		t.Fatalf("events: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		defer cancel()
		defer resp.Body.Close()
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read a refused stream: %v", err)
		}
		return nil, resp, body
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != streamReady {
		cancel()
		t.Fatalf("an admitted stream began with %q (%v)", line, err)
	}
	return func() {
		cancel()
		_ = resp.Body.Close()
	}, resp, nil
}

// admitStream opens a stream that must be admitted and returns its closer.
func admitStream(t *testing.T, srv *httptest.Server, u *user) func() {
	t.Helper()
	closer, resp, body := dialStream(t, srv, u)
	if closer == nil {
		t.Fatalf("a stream within the caps was refused: %d %q", resp.StatusCode, body)
	}
	return closer
}

// refuseStream opens a stream that must be refused with the registered answer of code.
func refuseStream(t *testing.T, srv *httptest.Server, u *user, code apperr.Code) {
	t.Helper()
	closer, resp, body := dialStream(t, srv, u)
	if closer != nil {
		closer()
		t.Fatal("a stream over a cap was admitted")
	}
	if !testutil.IsWireAnswer(resp, body, code) {
		id, _ := apperr.Describe(code)
		t.Fatalf("a stream over a cap: %d %q, want %s", resp.StatusCode, body, id)
	}
}

// admitOnceReleased retries a stream until a closed one's slot is released (bounded); every
// refusal on the way must be the cap's registered answer.
func admitOnceReleased(t *testing.T, srv *httptest.Server, u *user) func() {
	t.Helper()
	for attempt := 0; attempt < streamReleaseAttempts; attempt++ {
		closer, resp, body := dialStream(t, srv, u)
		if closer != nil {
			return closer
		}
		if !testutil.IsWireAnswer(resp, body, apperr.SubscriberLimit) {
			t.Fatalf("waiting for a released slot: %d %q", resp.StatusCode, body)
		}
		time.Sleep(streamReleasePause)
	}
	t.Fatal("a closed stream's slot was never released")
	return nil
}

func TestNegative_StreamsPerAccount(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	srv := streamServer(t, mux, newClient(t, mux).ip)
	closers := make([]func(), 0, realtime.MaxSubscribersPerMember)
	for i := 0; i < realtime.MaxSubscribersPerMember; i++ {
		closers = append(closers, admitStream(t, srv, alice)) // up to exactly the cap
	}
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	refuseStream(t, srv, alice, apperr.SubscriberLimit)
	// The cap is the account's, from any network
	refuseStream(t, streamServer(t, mux, newClient(t, mux).ip), alice, apperr.SubscriberLimit)
	// A refusal takes no slot: one closed stream makes room for exactly one
	closers[0]()
	closers[0] = admitOnceReleased(t, srv, alice)
	refuseStream(t, srv, alice, apperr.SubscriberLimit)
}

func TestNegative_StreamsPerClient(t *testing.T) {
	mux := setup(t)
	addr := newClient(t, mux).ip
	srv := streamServer(t, mux, addr)
	var closers []func()
	defer func() {
		for _, c := range closers {
			c()
		}
	}()
	for a := 0; a < streamAccountsPerClient; a++ {
		u := register(t, mux)
		for i := 0; i < realtime.MaxSubscribersPerMember; i++ {
			closers = append(closers, admitStream(t, srv, u)) // up to exactly the network's share
		}
	}
	extra := register(t, mux)
	refuseStream(t, srv, extra, apperr.SubscriberLimit)
	// The same account from another network is admitted: the share is the network's
	other := streamServer(t, mux, newClient(t, mux).ip)
	closers = append(closers, admitStream(t, other, extra))
}
