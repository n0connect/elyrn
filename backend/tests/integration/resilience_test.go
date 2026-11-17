package integration

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/database"
	"elyrn/internal/models"
	"elyrn/internal/server"
	"elyrn/internal/store"
	"elyrn/tests/testutil"

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
			if pool, err := broken.DB(); err == nil {
				_ = pool.Close()
			}
		}
	}
	t.Cleanup(restore)
	return restore
}

// stallWriteTimeout is the shipped SERVER_WRITE_TIMEOUT_SEC (.env.example), so the stall test
// proves the default configuration; stallClientTimeout bounds the test's own request.
const (
	stallWriteTimeout  = "15"
	stallClientTimeout = time.Minute
)

// stallDatabase points the request handle (database.DB) at a fresh pool behind a stalling proxy
// in front of the real PostgreSQL, built by database.Open from the configuration as production's
// is; the healthy handle comes back when the test ends.
func stallDatabase(t *testing.T) *testutil.StallingProxy {
	t.Helper()
	proxy := testutil.StartStallingProxy(t, net.JoinHostPort(config.GetDBHost(), config.GetDBPort()))
	t.Setenv("DB_HOST", "127.0.0.1")
	t.Setenv("DB_PORT", proxy.Port())
	stalled, err := database.Open(database.ConnectionURL())
	if err != nil {
		t.Fatalf("open the pool behind the proxy: %v", err)
	}
	healthy := database.DB
	database.DB = stalled
	t.Cleanup(func() {
		database.DB = healthy
		if pool, err := stalled.DB(); err == nil {
			_ = pool.Close()
		}
	})
	return proxy
}

// serveForReal serves mux from a real http.Server with the production configuration
// (server.NewHTTPServer: the configured write timeout above all), from one client address.
func serveForReal(t *testing.T, mux http.Handler) string {
	t.Helper()
	addr := newClient(t, mux).ip
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := server.NewHTTPServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = addr
		mux.ServeHTTP(w, r)
	}))
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + listener.Addr().String()
}

// postLogin sends one login over the network and reads the whole answer.
func postLogin(t *testing.T, base, authKey string) (*http.Response, []byte, error) {
	t.Helper()
	raw, err := json.Marshal(models.LoginRequest{AuthKey: authKey})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return overTheNetwork(t, http.MethodPost, base+models.PathLogin, raw, nil)
}

// overTheNetwork sends one request to a real server (a JSON body when raw is not nil, the
// session cookie when given) and reads the whole answer.
func overTheNetwork(t *testing.T, method, url string, raw []byte, cookie *http.Cookie) (*http.Response, []byte, error) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	client := &http.Client{Timeout: stallClientTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

// slowChunkDelay is how late the slowed proxy delivers each chunk: one statement (a request
// and an answer chunk) takes about twice this, well inside its own deadline (12 s with the
// shipped write timeout), while the several statements of one list request together take
// longer than the write timeout (15 s).
const slowChunkDelay = 1500 * time.Millisecond

// sseCommentPrefix starts an SSE comment line (the stream's ": ready" preamble), which a client
// ignores
const sseCommentPrefix = ":"

// The two lines of the stream's heartbeat (handlers' ssePing): sent once right after the preamble
// and then every sseKeepAlive, so an idle stream carries it too
var sseHeartbeatLines = map[string]bool{"event: ping": true, "data: {}": true}

// L-03: a request that runs several statements on a slow database, each one well inside its own
// deadline, still answers its registered 503 before the write deadline, because the whole
// request runs under one database deadline. With per-statement deadlines alone, the list below
// (the session, the member, the index, memberships, sequence numbers and room details: more
// than five statements of about 3 s each) outlived the write timeout and lost its answer.
func TestSlowDatabase_ARequestOfSeveralStatementsStillGetsIts503(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	pair(t, alice, bob)
	t.Setenv("SERVER_WRITE_TIMEOUT_SEC", stallWriteTimeout)
	proxy := stallDatabase(t)
	base := serveForReal(t, mux)
	list := base + models.PathConversations

	// Warm the pool and its prepared statements through the proxy, at full speed
	if resp, body, err := overTheNetwork(t, http.MethodGet, list, nil, alice.cookie); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("list through the proxy before the slowdown: %v %q", err, body)
	}
	proxy.Slow(slowChunkDelay)
	started := time.Now()
	resp, body, err := overTheNetwork(t, http.MethodGet, list, nil, alice.cookie)
	took := time.Since(started)
	proxy.Slow(0)
	if err != nil {
		t.Fatalf("the slow request got no complete answer after %s (the connection was cut): %v", took, err)
	}
	if !testutil.IsWireAnswer(resp, body, apperr.StoreUnavailable) {
		t.Fatalf("the slow request got %d %q after %s, want the registered E_STORE_UNAVAILABLE answer", resp.StatusCode, body, took)
	}
	if took >= config.GetServerWriteTimeout() {
		t.Fatalf("the 503 took %s, not within the write timeout %s", took, config.GetServerWriteTimeout())
	}
	if took < database.RequestBudget() {
		t.Fatalf("the 503 came after %s, before the request's database budget %s: something else failed", took, database.RequestBudget())
	}
}

// The event stream has no request deadline: it outlives the request budget (and the write
// timeout) and still delivers an event, on a real server with the production configuration.
func TestEvents_StreamOutlivesTheRequestDeadline(t *testing.T) {
	mux := setup(t)
	alice, bob := register(t, mux), register(t, mux)
	conv := pair(t, alice, bob)
	t.Setenv("SERVER_WRITE_TIMEOUT_SEC", stallWriteTimeout)
	base := serveForReal(t, mux)

	req, err := http.NewRequest(http.MethodGet, base+models.PathEvents, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.AddCookie(alice.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("events connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("events status %d", resp.StatusCode)
	}
	lines := make(chan string, 16)
	go func() {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		close(lines)
	}()
	waitFor(t, lines, "retry: 3000")

	// Until the request budget and the write timeout have both passed, the stream may carry only
	// what an idle stream writes: SSE comment lines (the preamble's ": ready"), the heartbeat sent
	// right after the preamble (a named ping event) and the blank lines that end them. Anything
	// else, or the stream closing, fails.
	outlive := time.After(max(database.RequestBudget(), config.GetServerWriteTimeout()) + time.Second)
	for idle := true; idle; {
		select {
		case line, open := <-lines:
			if !open {
				t.Fatal("the stream closed before the request deadline passed")
			}
			if line != "" && !strings.HasPrefix(line, sseCommentPrefix) && !sseHeartbeatLines[line] {
				t.Fatalf("unexpected line %q before any event", line)
			}
		case <-outlive:
			idle = false
		}
	}
	send(t, bob, alice, conv, 1)
	waitFor(t, lines, "event: msg")
}

// The drill: PostgreSQL stops answering (paused) under a running server. A request stalled on
// it must still get its registered 503 E_STORE_UNAVAILABLE written, in full, before net/http's
// write deadline: the database deadline of a request follows SERVER_WRITE_TIMEOUT_SEC. Before,
// both were 15 s, the 503 was written too late, and the client saw a cut connection (behind
// nginx, a 502).
func TestStalledDatabase_TheRequestStillGetsIts503(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	t.Setenv("SERVER_WRITE_TIMEOUT_SEC", stallWriteTimeout)
	proxy := stallDatabase(t)
	base := serveForReal(t, mux)

	if resp, _, err := postLogin(t, base, alice.authKey); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login through the proxy before the stall: %v", err)
	}
	proxy.Stall()
	defer proxy.Resume()
	started := time.Now()
	resp, body, err := postLogin(t, base, alice.authKey)
	took := time.Since(started)
	if err != nil {
		t.Fatalf("the stalled request got no complete answer after %s (the connection was cut): %v", took, err)
	}
	if !testutil.IsWireAnswer(resp, body, apperr.StoreUnavailable) {
		t.Fatalf("the stalled request got %d %q, want the registered E_STORE_UNAVAILABLE answer", resp.StatusCode, body)
	}
	if took >= config.GetServerWriteTimeout() {
		t.Fatalf("the 503 took %s, not within the write timeout %s", took, config.GetServerWriteTimeout())
	}
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

// A lookup the server cannot compute (here: no pepper) is its own fault, never "invalid
// credentials": 500 E_LOGIN_LOOKUP_FAILED, the same answer byte for byte for the key of an
// existing account and for a key that matches none, so it reveals no account either.
func TestLogin_LookupFailureIsAServerFaultForEveryKey(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	stranger := testutil.NewAuthKey(t)

	t.Setenv("ACCOUNT_LOOKUP_PEPPER", "")
	answers := make([]*httptest.ResponseRecorder, 0, 2)
	for _, key := range []string{alice.authKey, stranger} {
		rr := newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: key})
		if !testutil.IsAnswer(rr, apperr.LoginLookupFailed) {
			t.Fatalf("login without a pepper: %d %q, want the registered E_LOGIN_LOOKUP_FAILED answer", rr.Code, rr.Body.String())
		}
		answers = append(answers, rr)
	}
	if answers[0].Code != answers[1].Code || answers[0].Body.String() != answers[1].Body.String() {
		t.Fatal("an existing account and an unknown key got different answers")
	}
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

// logsDuring returns every line the standard logger wrote while fn ran, at LOG_LEVEL info (the
// production default; debug turns on GORM's statement log, which production refuses).
func logsDuring(t *testing.T, fn func()) string {
	t.Helper()
	t.Setenv("LOG_LEVEL", "info")
	var buf testutil.LockedLog
	defer testutil.RedirectStandardLog(&buf)()
	fn()
	return buf.String()
}

// brokenDatabaseText is what the driver's own text says of breakDatabase's address: the
// database user, name and host a log line must never carry (in production, the real ones).
var brokenDatabaseText = []string{"nobody", "database=none", "127.0.0.1:1", "failed to connect"}

// During an outage every repository and service that logs the failure logs its class only:
// no driver text (the database's user, name or host) reaches any log line.
func TestOutage_NoDriverTextReachesTheLog(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	logged := logsDuring(t, func() {
		restore := breakDatabase(t)
		defer restore()
		expectStatus(t, alice.do("GET", "/api/v2/me", nil), http.StatusServiceUnavailable, "session check during an outage")
		expectStatus(t, alice.do("GET", "/api/v2/conversations", nil), http.StatusServiceUnavailable, "list during an outage")
		expectStatus(t, newClient(t, mux).do("POST", "/api/v2/login", models.LoginRequest{AuthKey: alice.authKey}),
			http.StatusServiceUnavailable, "login during an outage")
	})
	for _, text := range brokenDatabaseText {
		if strings.Contains(logged, text) {
			t.Fatalf("driver text %q reached the log:\n%s", text, logged)
		}
	}
}

// A client that hangs up while its event stream starts never turns the stream's session and
// member lookups into "context canceled" answered as E_INTERNAL: the lookups run under the
// request's detached database context (middleware.StreamDeadline), the stream opens, and its loop
// ends at once because the client is gone.
func TestEvents_AClientGoneMidStartIsNoInternalError(t *testing.T) {
	mux := setup(t)
	alice := register(t, mux)
	req := httptest.NewRequest(http.MethodGet, models.PathEvents, nil)
	req.RemoteAddr = alice.ip
	req.AddCookie(alice.cookie)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	rr := httptest.NewRecorder()
	logged := logsDuring(t, func() { mux.ServeHTTP(rr, req.WithContext(ctx)) })
	if rr.Code != http.StatusOK {
		t.Fatalf("a stream whose client is gone answered %d %q, want the stream opened (200)", rr.Code, rr.Body.String())
	}
	for _, id := range []string{"E_INTERNAL", "context canceled"} {
		if strings.Contains(logged, id) {
			t.Fatalf("a client gone mid-start logged %q:\n%s", id, logged)
		}
	}
}
