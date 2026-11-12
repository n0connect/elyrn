package integration

import (
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/internal/store"

	"github.com/google/uuid"
)

// breakDatabase points the backend at a closed port until the returned func (or the test's
// end) restores it: every query fails exactly as it does while PostgreSQL is down. The broken
// handle is built by database.Open, as production's is, so its errors are classified the same.
func breakDatabase(t *testing.T) func() {
	t.Helper()
	healthy := database.DB
	broken, err := database.Open("postgres://nobody:nothing@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("open unreachable database: %v", err)
	}
	database.DB = broken
	restored := false
	restore := func() {
		if !restored {
			restored = true
			database.DB = healthy
		}
	}
	t.Cleanup(restore)
	return restore
}

// A database outage is not a wrong account number: telling the user "invalid credentials"
// would make them believe their only key is worthless.
func TestLogin_DatabaseOutageIsNotInvalidCredentials(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	restore := breakDatabase(t)
	rr := newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey})
	expectStatus(t, rr, http.StatusServiceUnavailable, "login during an outage")

	restore()
	expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}),
		http.StatusOK, "login after the outage")
}

// The account number is shown in phase 1 and saved by the user before phase 2 creates the
// account. A phase 2 that fails for a passing reason (database outage, saturated Argon2id)
// must leave it redeemable, or the number the user just saved is silently worthless.
func TestRegister_PassingFailureKeepsTheAccountNumber(t *testing.T) {
	mux := setup(t)
	c := newClient(t, mux)
	rr := c.do("POST", "/api/v2/register", models.RegisterRequest{Confirm: false, PoW: c.solvePoW()})
	expectStatus(t, rr, http.StatusOK, "register phase 1")
	var phase1 models.RegisterResponse
	decode(t, rr, &phase1)
	confirm := func() *models.RegisterRequest {
		return &models.RegisterRequest{Confirm: true, PendingToken: phase1.PendingToken, PoW: c.solvePoW()}
	}

	restore := breakDatabase(t)
	if rr := c.do("POST", "/api/v2/register", confirm()); rr.Code < 500 {
		t.Fatalf("phase 2 during an outage: status %d, want 5xx", rr.Code)
	}
	restore()

	release := auth.HoldArgon2SlotsForTesting()
	rr = c.do("POST", "/api/v2/register", confirm())
	release()
	expectStatus(t, rr, http.StatusServiceUnavailable, "phase 2 while saturated")

	expectStatus(t, c.do("POST", "/api/v2/register", confirm()), http.StatusCreated, "phase 2 retried")
	expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: registeredAuthKey(t, phase1.AccountNumber)}),
		http.StatusOK, "login with the saved number")

	// Created means used up: the token cannot create a second account
	expectStatus(t, c.do("POST", "/api/v2/register", confirm()), http.StatusUnauthorized, "phase 2 replayed")
}

// MAX_CONVERSATIONS_PER_USER only limits new conversations. An operator lowering it must
// not lock existing accounts out of their own conversations, nor out of burning or deleting.
func TestConversations_LoweredCapKeepsExistingAccountsWorking(t *testing.T) {
	mux := setup(t)
	alice, bob, carol, dave := register(t, mux), register(t, mux), register(t, mux), register(t, mux)
	first := pair(t, alice, bob)
	pair(t, alice, carol)

	t.Setenv("MAX_CONVERSATIONS_PER_USER", "1")
	rr := alice.do("GET", "/api/v2/conversations", nil)
	expectStatus(t, rr, http.StatusOK, "list above the lowered cap")
	var list models.ConversationsResponse
	decode(t, rr, &list)
	if len(list.Conversations) != 2 {
		t.Fatalf("listed %d conversations, want 2", len(list.Conversations))
	}

	rr = alice.createInvite()
	expectStatus(t, rr, http.StatusCreated, "invite")
	var invite models.InviteResponse
	decode(t, rr, &invite)
	expectStatus(t, dave.do("POST", "/api/v2/invites/redeem", models.RedeemInviteRequest{Token: invite.Token}),
		http.StatusTooManyRequests, "a third conversation")

	expectStatus(t, alice.do("DELETE", "/api/v2/conversations/"+first, nil), http.StatusNoContent, "burn above the cap")
	expectStatus(t, alice.do("DELETE", "/api/v2/me", models.DeleteAccountRequest{AuthKey: alice.authKey}),
		http.StatusOK, "delete above the cap")
}

// Lowering MESSAGE_TTL_DAYS also shortens what is already stored: no ciphertext outlives the
// retention the server now announces by more than that many days from now.
func TestRetention_LoweredTTLShortensStoredMessages(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)

	t.Setenv("MESSAGE_TTL_DAYS", "1")
	now := time.Now()
	if err := chat.NewService().PurgeExpired(now); err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if err := chat.NewService().PurgeExpired(now.Add(3 * 24 * time.Hour)); err != nil {
		t.Fatalf("PurgeExpired (3 days later): %v", err)
	}
	var left int64
	database.DB.Model(&models.Message{}).Count(&left)
	if left != 0 {
		t.Fatalf("%d messages outlived the lowered retention", left)
	}
}

// An outage answers 503 on authenticated routes too (the session check included), never 500 or
// a 401 that would log the user out.
func TestSession_DatabaseOutageIsUnavailable(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)

	restore := breakDatabase(t)
	expectStatus(t, alice.do("GET", "/api/v2/me", nil), http.StatusServiceUnavailable, "session check during an outage")
	expectStatus(t, alice.do("GET", "/api/v2/conversations", nil), http.StatusServiceUnavailable, "list during an outage")
	if alice.cookie == nil {
		t.Fatal("an outage cleared the session cookie")
	}

	restore()
	expectStatus(t, alice.do("GET", "/api/v2/me", nil), http.StatusOK, "session check after the outage")
}

// storedExpiry reads a message's deletion day straight from the table.
func storedExpiry(t *testing.T, conv string, seq int64) time.Time {
	t.Helper()
	var stored models.Message
	if err := database.DB.Where("conversation_id = ? AND seq = ?", conv, seq).First(&stored).Error; err != nil {
		t.Fatalf("message %d: %v", seq, err)
	}
	return stored.ExpiresOn.UTC()
}

// A clock moved back days and then corrected must not shorten any message's life: the cycle
// behind the last purge deletes nothing and caps nothing (E_CLOCK_JUMP).
func TestRetention_ClockMovedBackKillsNothingEarly(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	want := storedExpiry(t, conv, 1)

	svc := chat.NewService()
	now := time.Now()
	for _, at := range []time.Time{now, now.AddDate(0, 0, -5), now} {
		if err := svc.PurgeExpired(at); err != nil {
			t.Fatalf("PurgeExpired(%v): %v", at, err)
		}
	}
	if got := storedExpiry(t, conv, 1); !got.Equal(want) {
		t.Fatalf("expires_on moved from %v to %v by a clock that went back", want, got)
	}
}

// A clock far ahead of the last purge at boot (the first cycle) deletes nothing: it waits for a
// steady cycle, and the mark stays where it was, so the corrected clock purges normally.
func TestRetention_ForwardJumpDoesNotPurgeOnTheFirstCycle(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	want := storedExpiry(t, conv, 1)

	svc := chat.NewService()
	now := time.Now()
	farAhead := now.AddDate(0, 0, 2*365+1) // past twice the longest MESSAGE_TTL_DAYS
	for _, at := range []time.Time{now, farAhead, now} {
		if err := svc.PurgeExpired(at); err != nil {
			t.Fatalf("PurgeExpired(%v): %v", at, err)
		}
	}
	if got := storedExpiry(t, conv, 1); !got.Equal(want) {
		t.Fatalf("expires_on = %v after a forward jump, want %v", got, want)
	}
	rr := bob.do("GET", "/api/v2/conversations/"+conv+"/messages", nil)
	expectStatus(t, rr, http.StatusOK, "read after the jump")
	var msgs models.MessagesResponse
	decode(t, rr, &msgs)
	if len(msgs.Messages) != 1 {
		t.Fatalf("%d messages after a forward jump, want 1", len(msgs.Messages))
	}
}

// A message past its deletion day is never served, even while retention has not run.
func TestMessages_ExpiredNeverListedBeforePurge(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	send(t, alice, bob, conv, 1)
	send(t, alice, bob, conv, 2)
	database.DB.Model(&models.Message{}).Where("conversation_id = ? AND seq = 1", conv).
		UpdateColumn("expires_on", time.Now().UTC().AddDate(0, 0, -1))

	for _, path := range []string{"/messages", "/messages?after=0", "/messages?before=3"} {
		rr := bob.do("GET", "/api/v2/conversations/"+conv+path, nil)
		expectStatus(t, rr, http.StatusOK, "read "+path)
		var msgs models.MessagesResponse
		decode(t, rr, &msgs)
		if len(msgs.Messages) != 1 || msgs.Messages[0].Seq != 2 {
			t.Fatalf("%s served %+v, want only seq 2", path, msgs.Messages)
		}
	}
}

// memberOf resolves a test user to the chat service's member, as a request would.
func memberOf(t *testing.T, svc *chat.Service, u *user) *chat.Member {
	t.Helper()
	lookup, err := auth.ComputeAccountLookup(u.authKey)
	if err != nil {
		t.Fatalf("ComputeAccountLookup: %v", err)
	}
	row, err := store.NewUserRepository().FindByAccountLookup(lookup)
	if err != nil {
		t.Fatalf("FindByAccountLookup: %v", err)
	}
	member, err := svc.ResolveMember(row.UUID)
	if err != nil {
		t.Fatalf("ResolveMember: %v", err)
	}
	return member
}

// A burn racing sends leaves no ciphertext behind: each send either commits before the burn
// (and is burned with the rest) or finds no conversation (404).
func TestBurn_RacingSendsLeaveNoCiphertext(t *testing.T) {
	const (
		rounds         = 15
		sendsPerRound  = 4
		expectedErrors = rounds * (sendsPerRound + 1)
	)
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	svc := chat.NewService()
	sender, burner := memberOf(t, svc, alice), memberOf(t, svc, bob)

	for round := 0; round < rounds; round++ {
		conv := pair(t, alice, bob)
		convID := uuid.MustParse(conv)
		ids := make([]string, sendsPerRound)
		sealed := make([]string, sendsPerRound)
		for i := range ids {
			ids[i] = newMessageID()
			sealed[i] = seal(t, alice, bob, conv, ids[i], "racing", int64(i+1))
		}

		start := make(chan struct{})
		failures := make(chan error, expectedErrors)
		var wg sync.WaitGroup
		for i := range ids {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if _, _, err := svc.SendMessage(sender, convID, ids[i], sealed[i]); err != nil && !errors.Is(err, chat.ErrNotFound) {
					failures <- err
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := svc.BurnConversation(burner, convID); err != nil {
				failures <- err
			}
		}()
		close(start)
		wg.Wait()
		close(failures)
		for err := range failures {
			t.Fatalf("round %d: unexpected error %v", round, err)
		}

		var left int64
		database.DB.Model(&models.Message{}).Where("conversation_id = ?", convID).Count(&left)
		if left != 0 {
			t.Fatalf("round %d: %d messages outlived the burn of their conversation", round, left)
		}
	}
}
