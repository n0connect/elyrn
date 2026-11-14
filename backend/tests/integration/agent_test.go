package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/e2e"
	"elyrn/internal/identity"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// Two robots (internal/agent, the program behind elyrn-agent) and one browser-style user share a
// room through the real server over real HTTP. The robots solve the server's real proofs of work:
// both registrations and the room cost five challenges from 127.0.0.1, exactly the per-client
// budget of one minute, so this flow registers no other robot.

const agentWait = 10 * time.Second

// newIdentityPath is where an agent named name keeps its identity under dir. The directory does not
// exist yet, so the agent creates it private (0700) itself; t.TempDir() is 0755 on Linux and the
// agent rightly refuses an identity directory open to other users.
func newIdentityPath(dir, name string) string {
	return filepath.Join(dir, name, "agent.json")
}

func newAgent(t *testing.T, server, path string) *agent.Agent {
	t.Helper()
	a, err := agent.New(agent.Config{Server: server, IdentityPath: path})
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	t.Cleanup(a.Close)
	return a
}

func agentIdentity(t *testing.T, a *agent.Agent, created bool) *agent.IdentityResult {
	t.Helper()
	id, err := a.Identity(context.Background())
	if err != nil || id.Created != created || id.Name == "" || id.PublicKey == "" {
		t.Fatalf("Identity = %+v, %v (want created=%v)", id, err, created)
	}
	return id
}

func agentSend(t *testing.T, a *agent.Agent, room uuid.UUID, text string) int64 {
	t.Helper()
	sent, err := a.Send(context.Background(), room, text)
	if err != nil || !sent.Stored || sent.Seq == nil || *sent.Seq < 1 {
		t.Fatalf("Send %q = %+v, %v", text, sent, err)
	}
	return *sent.Seq
}

// agentRead reads and insists on a gap-free history: every sender's counter is consecutive.
func agentRead(t *testing.T, a *agent.Agent, room uuid.UUID, after *int64) *agent.ReadResult {
	t.Helper()
	got, err := a.Read(context.Background(), room, after)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.Gaps) != 0 {
		t.Fatalf("Read reported gaps %+v in a gap-free room", got.Gaps)
	}
	for _, m := range got.Messages {
		if m.Broken {
			t.Fatalf("message %d did not open", m.Seq)
		}
	}
	return got
}

func texts(r *agent.ReadResult) []string {
	out := make([]string, len(r.Messages))
	for i, m := range r.Messages {
		out[i] = m.Text
	}
	return out
}

// selfName is the name this agent's members listing marks as mine.
func selfName(t *testing.T, a *agent.Agent, room uuid.UUID, wantMembers int) (string, string) {
	t.Helper()
	members, err := a.Members(context.Background(), room)
	if err != nil || len(members.Members) != wantMembers || members.UnverifiedCards != 0 {
		t.Fatalf("Members = %+v, %v (want %d)", members, err, wantMembers)
	}
	name, mine, owners := "", 0, 0
	for _, m := range members.Members {
		if m.Mine {
			name = m.Name
			mine++
		}
		if m.Owner {
			owners++
		}
	}
	if mine != 1 || owners != 1 {
		t.Fatalf("Members marks %d as mine and %d as owner", mine, owners)
	}
	return name, members.SafetyNumber
}

func TestAgents_TalkInARoomWithABrowserUser(t *testing.T) {
	mux := setup(t)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	ctx := context.Background()
	dir := t.TempDir()
	alphaPath := newIdentityPath(dir, "alpha")
	alpha := newAgent(t, srv.URL, alphaPath)
	beta := newAgent(t, srv.URL, newIdentityPath(dir, "beta"))
	if agentIdentity(t, alpha, true).PublicKey == agentIdentity(t, beta, true).PublicKey {
		t.Fatal("two agents share a public key")
	}

	created, err := alpha.CreateRoom(ctx, 4, 24)
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	room := uuid.MustParse(created.Room)
	joined, err := beta.JoinRoom(ctx, created.Code)
	if err != nil || joined.Room != created.Room || joined.Name != created.Name || joined.Members != 2 {
		t.Fatalf("JoinRoom = %+v, %v", joined, err)
	}
	// The same room's code with other limits is well formed but altered: its own code, its own sentence
	altered, err := e2e.ParseRoomCode(created.Code)
	if err != nil {
		t.Fatalf("ParseRoomCode: %v", err)
	}
	for what, change := range map[string]func(*e2e.RoomCode){
		"more seats":     func(c *e2e.RoomCode) { c.MaxMembers++ },
		"a later expiry": func(c *e2e.RoomCode) { c.ExpiresHour++ },
	} {
		doctored := *altered
		change(&doctored)
		if _, err := beta.JoinRoom(ctx, doctored.String()); agent.CodeOf(err) != agent.CodeRoomCodeAltered {
			t.Fatalf("joining a room already held with %s: %v, want %s", what, err, agent.CodeRoomCodeAltered)
		}
	}
	alphaName, alphaSafety := selfName(t, alpha, room, 2)
	betaName, betaSafety := selfName(t, beta, room, 2)
	if alphaSafety != betaSafety || alphaName == betaName {
		t.Fatalf("safety numbers %q / %q, names %q / %q", alphaSafety, betaSafety, alphaName, betaName)
	}

	agentSend(t, alpha, room, "hello beta")
	agentSend(t, beta, room, "hello alpha")
	last := agentSend(t, alpha, room, "how are you")
	got := agentRead(t, beta, room, nil)
	if !slices.Equal(texts(got), []string{"hello beta", "hello alpha", "how are you"}) || got.LastSeq != last {
		t.Fatalf("beta read %+v", got)
	}
	for i, wantMine := range []bool{false, true, false} {
		wantSender := map[bool]string{false: alphaName, true: betaName}[wantMine]
		if got.Messages[i].Mine != wantMine || got.Messages[i].Sender != wantSender {
			t.Fatalf("message %d: %+v", i, got.Messages[i])
		}
	}

	carol := agentsMeetABrowserUser(t, mux, alpha, room, created.Code, last)
	agentsWaitAndLeave(t, alpha, beta, carol, room)
	alpha.Close() // a restart: the identity's lock is free again only once alpha has stopped
	agentReloads(t, srv.URL, alphaPath)
}

// agentsMeetABrowserUser: carol joins with the browser protocol while alpha still holds the old
// roster, so alpha's next send is refused with 412 and must be re-encrypted for carol.
func agentsMeetABrowserUser(t *testing.T, mux http.Handler, alpha *agent.Agent, room uuid.UUID, codeText string, last int64) *roomSide {
	t.Helper()
	code, err := e2e.ParseRoomCode(codeText)
	if err != nil {
		t.Fatalf("ParseRoomCode: %v", err)
	}
	carolUser := register(t, mux)
	carol := joinRoom(t, carolUser, code)

	seq := agentSend(t, alpha, room, "carol is here")
	heard := carol.read(t)
	if len(heard) != 1 || heard[0].text != "carol is here" {
		t.Fatalf("carol heard %+v: alpha did not re-encrypt for the new roster", heard)
	}
	carol.say(t, "hello robots", 1)
	got := agentRead(t, alpha, room, &seq)
	carolAura, err := e2e.AuraOf(carol.member.Public)
	if err != nil {
		t.Fatalf("AuraOf: %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Text != "hello robots" || got.Messages[0].Mine ||
		got.Messages[0].Sender != carolAura.Name || got.LastSeq <= last {
		t.Fatalf("alpha read %+v, want carol's message from %s", got, carolAura.Name)
	}
	return carol
}

func agentsWaitAndLeave(t *testing.T, alpha, beta *agent.Agent, carol *roomSide, room uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	caughtUp := agentRead(t, beta, room, nil).LastSeq
	waited := make(chan *agent.ReadResult, 1)
	go func() {
		got, err := beta.Wait(ctx, room, caughtUp, agentWait)
		if err != nil {
			got = nil
		}
		waited <- got
	}()
	agentSend(t, alpha, room, "wake up")
	got := <-waited
	if got == nil || got.TimedOut || !slices.Equal(texts(got), []string{"wake up"}) || len(got.Gaps) != 0 {
		t.Fatalf("Wait = %+v", got)
	}
	idle, err := beta.Wait(ctx, room, got.LastSeq, time.Second)
	if err != nil || !idle.TimedOut || len(idle.Messages) != 0 {
		t.Fatalf("an idle Wait = %+v, %v", idle, err)
	}

	listed, err := alpha.Rooms(ctx)
	if err != nil || len(listed.Rooms) != 1 || listed.Rooms[0].Room != room.String() || !listed.Rooms[0].Owner || listed.Rooms[0].Members != 3 {
		t.Fatalf("alpha's rooms = %+v, %v", listed, err)
	}
	left, err := beta.Leave(ctx, room)
	if err != nil || left.Burned {
		t.Fatalf("beta Leave = %+v, %v", left, err)
	}
	if listed, err := beta.Rooms(ctx); err != nil || len(listed.Rooms) != 0 {
		t.Fatalf("beta still lists %+v, %v", listed, err)
	}
	selfName(t, alpha, room, 2)
	if left, err = alpha.Leave(ctx, room); err != nil || !left.Burned {
		t.Fatalf("owner Leave = %+v, %v", left, err)
	}
	if conv := findConversation(listOf(t, carol.u), room.String()); conv != nil {
		t.Fatal("the burned room is still listed for carol")
	}
	if _, err := alpha.Read(ctx, room, nil); agent.CodeOf(err) != agent.CodeRoomUnknown {
		t.Fatalf("reading a burned room: %v", err)
	}
}

// agentReloads starts alpha again from its identity file: private permissions (the counter
// file's too), a confirmed identity in the released format, the same identity through a fresh
// login, one agent per identity with whoami beside it, and refusal of another server or wider
// permissions.
func agentReloads(t *testing.T, server, path string) {
	t.Helper()
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700, agentCounterFile(path): 0o600} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v (want %v)", filepath.Base(p), info.Mode().Perm(), err, want)
		}
	}
	if fields := identityFields(t, path); len(fields) != 2 {
		t.Fatalf("a confirmed identity file holds %d fields, want server and account_number only", len(fields))
	}
	first := newAgent(t, "", path)
	who, err := first.Whoami()
	if err != nil || who.Server != server {
		t.Fatalf("Whoami = %+v, %v", who, err)
	}
	if again := agentIdentity(t, first, false); again.PublicKey != who.PublicKey || again.Name != who.Name {
		t.Fatalf("the reloaded identity differs: %+v vs %+v", again, who)
	}
	if _, err := agent.New(agent.Config{IdentityPath: path}); agent.CodeOf(err) != agent.CodeIdentityInUse {
		t.Fatalf("a second agent on a running identity: %v", err)
	}
	reader, err := agent.New(agent.Config{IdentityPath: path, ReadOnly: true})
	if err != nil {
		t.Fatalf("a read-only agent beside the running one: %v", err)
	}
	t.Cleanup(reader.Close)
	if beside, err := reader.Whoami(); err != nil || beside.PublicKey != who.PublicKey {
		t.Fatalf("whoami beside the running agent = %+v, %v", beside, err)
	}
	first.Close()
	_, err = agent.New(agent.Config{Server: "https://elsewhere.example", IdentityPath: path})
	if agent.CodeOf(err) != agent.CodeServerMismatch {
		t.Fatalf("another server: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := agent.New(agent.Config{IdentityPath: path}); agent.CodeOf(err) != agent.CodeIdentityPermissions {
		t.Fatalf("a world-readable identity file was accepted: %v", err)
	}
}

// ---------- situations: restarts, lost answers, failed checks, replays, dying streams ----------

const (
	situationMembers  = 3
	situationTTLHours = 168 // a week: outlives the retention purge below
	// The purge that deletes the agent's messages: retention lowered to one day, three days on
	situationTTLDays  = "1"
	situationPurgeDay = 3 * 24 * time.Hour
	// The wait test: a short timeout to sit out, and when the browser user speaks during a wait
	situationShortWait = 3 * time.Second
	situationLongWait  = 15 * time.Second
	situationSpeakIn   = 500 * time.Millisecond
	// The registration lives one second (PENDING_TOKEN_TTL_SEC); this is surely past it
	situationExpiry = 2 * time.Second
)

func agentCounterFile(identityPath string) string {
	return filepath.Join(filepath.Dir(identityPath), "agent.counters.json")
}

// identityFields returns the field names of the identity file (never their values).
func identityFields(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read identity file: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("the identity file is not a JSON object")
	}
	return fields
}

// hostileServer serves the real mux over real HTTP from a fresh client address (its own PoW
// budget), except for the requests intercept takes over: the misbehaving server a scenario
// needs and the real server cannot be made to be.
func hostileServer(t *testing.T, mux http.Handler, intercept func(http.ResponseWriter, *http.Request) bool) *httptest.Server {
	t.Helper()
	addr := newClient(t, mux).ip
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = addr
		if !intercept(w, r) {
			mux.ServeHTTP(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// agentWithRoom registers a robot through srv, creates a room and seats a browser user in it.
func agentWithRoom(t *testing.T, mux http.Handler, srv *httptest.Server, path string) (*agent.Agent, uuid.UUID, *roomSide) {
	t.Helper()
	robot := newAgent(t, srv.URL, path)
	created, err := robot.CreateRoom(context.Background(), situationMembers, situationTTLHours)
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	code, err := e2e.ParseRoomCode(created.Code)
	if err != nil {
		t.Fatalf("ParseRoomCode: %v", err)
	}
	return robot, uuid.MustParse(created.Room), joinRoom(t, register(t, mux), code)
}

// countersHeard opens every message the browser user can read and returns their counters.
func countersHeard(t *testing.T, s *roomSide) []int64 {
	t.Helper()
	rr := s.u.do("GET", s.path("/messages"), nil)
	expectStatus(t, rr, http.StatusOK, "room read")
	var resp models.MessagesResponse
	decode(t, rr, &resp)
	counters := make([]int64, 0, len(resp.Messages))
	for _, m := range resp.Messages {
		msg, err := s.room.OpenMessage(s.member, uuid.MustParse(m.ID), m.Ciphertext)
		if err != nil {
			t.Fatalf("OpenMessage seq %d: %v", m.Seq, err)
		}
		counters = append(counters, msg.Counter)
	}
	return counters
}

// A-01: the agent's own messages expire, the agent restarts, and its next message must still
// carry a fresh counter, or every browser hides it as a replay while the agent reports it
// stored. The counter file remembers what the visible messages no longer show.
func TestAgent_CountersSurviveARestartAfterTheirMessagesExpired(t *testing.T) {
	mux := setup(t)
	srv := clientServer(t, mux)
	path := newIdentityPath(t.TempDir(), "robot")
	robot, room, carol := agentWithRoom(t, mux, srv, path)
	agentSend(t, robot, room, "one")
	agentSend(t, robot, room, "two")
	if got := countersHeard(t, carol); !slices.Equal(got, []int64{1, 2}) {
		t.Fatalf("counters before the restart: %v", got)
	}
	robot.Close()

	t.Setenv("MESSAGE_TTL_DAYS", situationTTLDays)
	now := time.Now()
	for _, at := range []time.Time{now, now.Add(situationPurgeDay)} {
		if err := chat.NewService().PurgeExpired(at); err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
	}
	if got := countersHeard(t, carol); len(got) != 0 {
		t.Fatalf("the purge left %d messages", len(got))
	}

	restarted := newAgent(t, "", path)
	agentSend(t, restarted, room, "three")
	if got := countersHeard(t, carol); !slices.Equal(got, []int64{3}) {
		t.Fatalf("after the restart the counter went %v, want [3]: browsers would hide it as a replay", got)
	}
}

// A-02: registration phase 2 fails (the server is saturated); the identity file keeps the
// pending token, and the next run finishes the registration while the server still holds it.
func TestAgent_AnUnconfirmedRegistrationIsFinishedByTheNextRun(t *testing.T) {
	srv := clientServer(t, setup(t))
	path := newIdentityPath(t.TempDir(), "robot")
	robot := newAgent(t, srv.URL, path)
	release := auth.HoldArgon2SlotsForTesting()
	_, err := robot.Identity(context.Background())
	release()
	if agent.CodeOf(err) != agent.CodeServerBusy {
		t.Fatalf("Identity on a saturated server: %v, want %s", err, agent.CodeServerBusy)
	}
	if _, pending := identityFields(t, path)["pending_token"]; !pending {
		t.Fatal("the identity file does not keep the pending registration")
	}
	robot.Close()

	restarted := newAgent(t, "", path)
	agentIdentity(t, restarted, false)
	if _, pending := identityFields(t, path)["pending_token"]; pending {
		t.Fatal("the pending token stayed in the identity file after the account was confirmed")
	}
	if _, err := restarted.Rooms(context.Background()); err != nil {
		t.Fatalf("Rooms after the finished registration: %v", err)
	}
}

// A-02: when the server no longer holds the registration, the agent says the identity was never
// confirmed (and can be replaced without loss), not that the server forgot an account.
func TestAgent_AnExpiredRegistrationSaysItWasNeverConfirmed(t *testing.T) {
	srv := clientServer(t, setup(t))
	t.Setenv("PENDING_TOKEN_TTL_SEC", "1")
	path := newIdentityPath(t.TempDir(), "robot")
	robot := newAgent(t, srv.URL, path)
	release := auth.HoldArgon2SlotsForTesting()
	_, err := robot.Identity(context.Background())
	release()
	// Saturated until the end, or the registration already expired between two retries
	if code := agent.CodeOf(err); code != agent.CodeServerBusy && code != agent.CodeIdentityUnconfirmed {
		t.Fatalf("Identity on a saturated server: %v", err)
	}
	if _, pending := identityFields(t, path)["pending_token"]; !pending {
		t.Fatal("the identity file does not keep the pending registration")
	}
	time.Sleep(situationExpiry)
	_, err = robot.Identity(context.Background())
	if agent.CodeOf(err) != agent.CodeIdentityUnconfirmed {
		t.Fatalf("Identity after the registration expired: %v, want %s", err, agent.CodeIdentityUnconfirmed)
	}
}

// A-03: a server that serves another public key on /me. The failed check must leave no session
// behind: every later call checks again and fails the same way (never a crash on the missing
// limits), and once the server serves the right key the agent works.
func TestAgent_AFailedMeCheckLeavesNoSession(t *testing.T) {
	mux := setup(t)
	other, err := utils.GenerateAccountNumber()
	if err != nil {
		t.Fatalf("GenerateAccountNumber: %v", err)
	}
	otherKey, err := identity.DerivePublicKey(other)
	if err != nil {
		t.Fatalf("DerivePublicKey: %v", err)
	}
	var lie atomic.Bool
	lie.Store(true)
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if !lie.Load() || r.Method != http.MethodGet || r.URL.Path != models.PathMe {
			return false
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		var me models.MeResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &me) != nil {
			t.Errorf("the real /me answered %d", rr.Code)
			return false
		}
		me.PublicKey = otherKey
		for name, values := range rr.Header() {
			w.Header()[name] = values
		}
		w.Header().Del("Content-Length") // the body below is re-encoded
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&me)
		return true
	})
	ctx := context.Background()
	robot := newAgent(t, srv.URL, newIdentityPath(t.TempDir(), "robot"))
	if _, err := robot.Identity(ctx); agent.CodeOf(err) != agent.CodeIdentityMismatch {
		t.Fatalf("Identity against another key: %v, want %s", err, agent.CodeIdentityMismatch)
	}
	if _, err := robot.CreateRoom(ctx, situationMembers, situationTTLHours); agent.CodeOf(err) != agent.CodeIdentityMismatch {
		t.Fatalf("CreateRoom after a failed check: %v, want %s", err, agent.CodeIdentityMismatch)
	}
	if _, err := robot.Rooms(ctx); agent.CodeOf(err) != agent.CodeIdentityMismatch {
		t.Fatalf("Rooms after a failed check: %v, want %s", err, agent.CodeIdentityMismatch)
	}
	lie.Store(false)
	if _, err := robot.CreateRoom(ctx, situationMembers, situationTTLHours); err != nil {
		t.Fatalf("CreateRoom once the server serves the right key: %v", err)
	}
}

// A-04: a member (or the server) serving an old counter under a new seq. The message is reported
// as a replay without its text, never delivered as new; reading the same page again does not
// turn it into history; a restart remembers the counters (counter file); room_wait reports it
// as room_read does.
func TestAgent_ReplayedCountersAreNotDeliveredAsNew(t *testing.T) {
	mux := setup(t)
	path := newIdentityPath(t.TempDir(), "robot")
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), path)
	ctx := context.Background()
	carol.say(t, "first", 1)
	first := agentRead(t, robot, room, nil)
	if !slices.Equal(texts(first), []string{"first"}) || len(first.Replays) != 0 {
		t.Fatalf("first read %+v", first)
	}

	carol.say(t, "again", 1)
	again := agentRead(t, robot, room, &first.LastSeq)
	if len(again.Messages) != 0 || len(again.Replays) != 1 || again.Replays[0].Mine || again.Replays[0].Seq != again.LastSeq {
		t.Fatalf("a repeated counter was not reported as a replay: %+v", again)
	}
	carol.say(t, "next", 2)
	next := agentRead(t, robot, room, &again.LastSeq)
	if !slices.Equal(texts(next), []string{"next"}) || len(next.Replays) != 0 {
		t.Fatalf("the message after a replay: %+v", next)
	}
	whole := agentRead(t, robot, room, nil)
	if !slices.Equal(texts(whole), []string{"first", "next"}) || len(whole.Replays) != 1 {
		t.Fatalf("reading the page again delivered the replay: %+v", whole)
	}
	robot.Close()

	restarted := newAgent(t, "", path)
	carol.say(t, "stale", 2)
	stale, err := restarted.Read(ctx, room, &next.LastSeq)
	if err != nil || len(stale.Messages) != 0 || len(stale.Replays) != 1 {
		t.Fatalf("after a restart a repeated counter was delivered: %+v, %v", stale, err)
	}
	waited := make(chan *agent.ReadResult, 1)
	go func() {
		got, err := restarted.Wait(ctx, room, stale.LastSeq, agentWait)
		if err != nil {
			got = nil
		}
		waited <- got
	}()
	time.Sleep(situationSpeakIn)
	carol.say(t, "older", 1)
	got := <-waited
	if got == nil || got.TimedOut || len(got.Messages) != 0 || len(got.Replays) != 1 {
		t.Fatalf("room_wait on a replay = %+v", got)
	}
}

// A-05: a server whose event stream cannot be held. room_wait falls back to reading the room,
// never reports timed_out before its timeout has passed, and still returns a message sent
// during the wait. A-07: Close while a cancelled wait is still returning neither races nor
// panics, and the agent refuses calls afterwards.
func TestAgent_WaitOutlivesAStreamThatCannotBeHeld(t *testing.T) {
	mux := setup(t)
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != models.PathEvents {
			return false
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	robot, room, carol := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	ctx := context.Background()
	caughtUp := agentRead(t, robot, room, nil).LastSeq

	started := time.Now()
	idle, err := robot.Wait(ctx, room, caughtUp, situationShortWait)
	if err != nil || !idle.TimedOut || len(idle.Messages) != 0 {
		t.Fatalf("an idle wait without a stream = %+v, %v", idle, err)
	}
	if elapsed := time.Since(started); elapsed < situationShortWait {
		t.Fatalf("timed_out after %v, before the %v timeout", elapsed, situationShortWait)
	}

	waited := make(chan *agent.ReadResult, 1)
	go func() {
		got, err := robot.Wait(ctx, room, caughtUp, situationLongWait)
		if err != nil {
			got = nil
		}
		waited <- got
	}()
	time.Sleep(situationSpeakIn)
	carol.say(t, "are you there", 1)
	got := <-waited
	if got == nil || got.TimedOut || !slices.Equal(texts(got), []string{"are you there"}) {
		t.Fatalf("a wait without a stream missed the message: %+v", got)
	}

	cancelled, cancel := context.WithCancel(ctx)
	ended := make(chan error, 1)
	go func() {
		_, err := robot.Wait(cancelled, room, got.LastSeq, situationLongWait)
		ended <- err
	}()
	time.Sleep(situationSpeakIn)
	cancel()
	robot.Close()
	if err := <-ended; err == nil {
		t.Fatal("a cancelled wait reported success")
	}
	if _, err := robot.Rooms(ctx); agent.CodeOf(err) != agent.CodeStopped {
		t.Fatalf("a call after Close: %v, want %s", err, agent.CodeStopped)
	}
}

// A-06: the server stores the room but its answer is lost. The agent finds the room in its
// listing and returns it, code included, instead of a network error that invites a second room.
func TestAgent_ALostCreateAnswerSettlesTheStoredRoom(t *testing.T) {
	mux := setup(t)
	var dropped atomic.Bool
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPost || r.URL.Path != models.PathRooms || !dropped.CompareAndSwap(false, true) {
			return false
		}
		mux.ServeHTTP(httptest.NewRecorder(), r) // stored, and the answer goes nowhere
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return true
		}
		_ = conn.Close()
		return true
	})
	ctx := context.Background()
	robot := newAgent(t, srv.URL, newIdentityPath(t.TempDir(), "robot"))
	created, err := robot.CreateRoom(ctx, situationMembers, situationTTLHours)
	if err != nil || !dropped.Load() || created.Code == "" {
		t.Fatalf("CreateRoom with a lost answer = %+v, %v", created, err)
	}
	listed, err := robot.Rooms(ctx)
	if err != nil || len(listed.Rooms) != 1 || listed.Rooms[0].Room != created.Room {
		t.Fatalf("rooms after the lost answer = %+v, %v (want exactly the one created)", listed, err)
	}
	if _, err := e2e.ParseRoomCode(created.Code); err != nil {
		t.Fatalf("the settled code does not parse: %v", err)
	}
}

// isMessagesRead reports whether r reads a conversation's messages.
func isMessagesRead(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, models.PathConversations+"/") &&
		strings.HasSuffix(r.URL.Path, "/"+models.SubMessages)
}

// answerJSON writes status and a JSON body as nginx's own answers come.
func answerJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// A hostile server hides a room from one listing, then answers 404 for it once: neither is a
// fact the agent prunes its counter record on. An old counter served afterwards under a new seq
// is still a replay, in the same run and after a restart, and the agent's own counter never
// goes backwards.
func TestAgent_AHiddenRoomKeepsItsCounterRecord(t *testing.T) {
	mux := setup(t)
	var hide, gone atomic.Bool
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == models.PathConversations && hide.CompareAndSwap(true, false):
			answerJSON(w, http.StatusOK, `{"conversations":[]}`)
			return true
		case isMessagesRead(r) && gone.CompareAndSwap(true, false):
			http.Error(w, "Not found", http.StatusNotFound) // the backend's own 404
			return true
		}
		return false
	})
	ctx := context.Background()
	path := newIdentityPath(t.TempDir(), "robot")
	robot, room, carol := agentWithRoom(t, mux, srv, path)
	agentSend(t, robot, room, "mine")
	carol.say(t, "first", 1)
	first := agentRead(t, robot, room, nil)
	if !slices.Equal(texts(first), []string{"mine", "first"}) {
		t.Fatalf("first read %+v", first)
	}

	hide.Store(true)
	if listed, err := robot.Rooms(ctx); err != nil || len(listed.Rooms) != 0 {
		t.Fatalf("the hidden listing = %+v, %v", listed, err)
	}
	gone.Store(true)
	if _, err := robot.Read(ctx, room, &first.LastSeq); agent.CodeOf(err) != agent.CodeRoomUnknown {
		t.Fatalf("a read answered 404: %v, want %s", err, agent.CodeRoomUnknown)
	}
	carol.say(t, "again", 1)
	again, err := robot.Read(ctx, room, &first.LastSeq)
	if err != nil || len(again.Messages) != 0 || len(again.Replays) != 1 || again.Replays[0].Mine {
		t.Fatalf("after the room was hidden an old counter was not a replay: %+v, %v", again, err)
	}
	robot.Close()

	restarted := newAgent(t, "", path)
	carol.say(t, "stale", 1)
	stale, err := restarted.Read(ctx, room, &again.LastSeq)
	if err != nil || len(stale.Messages) != 0 || len(stale.Replays) != 1 {
		t.Fatalf("after a restart an old counter was not a replay: %+v, %v", stale, err)
	}
	agentSend(t, restarted, room, "after")
	if got := countersHeard(t, carol); !slices.Equal(got, []int64{1, 1, 1, 1, 2}) {
		t.Fatalf("counters heard %v, want [1 1 1 1 2]: the agent's own counter went backwards", got)
	}
}

// A history page (before) is held under the ceiling of what was already read above it, as the
// browser's counters.js history/lowest do: a message below whose counter is not under its
// sender's lowest counter above is a replay or a reorder, listed in replays and never delivered.
func TestAgent_HistoryPagesStayBelowTheirCeiling(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	ctx := context.Background()
	agentSend(t, robot, room, "hello") // the counter sync runs now, on an empty room
	carol.say(t, "one", 1)
	carol.say(t, "high", 5) // a lower seq than "low" below, yet a higher counter: out of order
	mark := agentSend(t, robot, room, "mark")
	carol.say(t, "low", 2)
	if got := agentRead(t, robot, room, &mark); !slices.Equal(texts(got), []string{"low"}) || len(got.Replays) != 0 {
		t.Fatalf("the read above the mark = %+v", got)
	}

	for range 2 { // reading the page again must not turn the replay into history
		page, err := robot.ReadBefore(ctx, room, mark)
		if err != nil || !slices.Equal(texts(page), []string{"hello", "one"}) || len(page.Gaps) != 0 ||
			len(page.Replays) != 1 || page.Replays[0].Mine || page.Replays[0].Seq <= page.Messages[1].Seq || page.Replays[0].Seq >= mark {
			t.Fatalf("the history page = %+v, %v (want hello and one delivered, high listed as a replay)", page, err)
		}
	}
}

// nginx answers its own /api/ failures as JSON with a registered edge id. An edge 404 (or any
// edge refusal) is never read as "the room is gone"; an unavailable backend is a passing
// failure; a JSON body with an unknown id falls back to the status; a known id under another
// status below 500 is a malformed answer, while any 5xx is a passing failure whatever its body
// (an nginx deployed before its error pages stated their status answered a backend cut off
// mid-answer with 502 or 504 and the 503 id: the drill's database pause). The room and its
// counter record survive all of it.
func TestAgent_EdgeAnswersAreNotTheRoomsAnswers(t *testing.T) {
	mux := setup(t)
	type reply struct {
		status int
		body   string
	}
	var next atomic.Pointer[reply]
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		if !isMessagesRead(r) {
			return false
		}
		served := next.Swap(nil)
		if served == nil {
			return false
		}
		answerJSON(w, served.status, served.body)
		return true
	})
	ctx := context.Background()
	robot, room, carol := agentWithRoom(t, mux, srv, newIdentityPath(t.TempDir(), "robot"))
	carol.say(t, "first", 1)
	first := agentRead(t, robot, room, nil)

	want := map[string]agent.Code{
		"E_BACKEND_UNAVAILABLE":     agent.CodeServerBusy,
		"E_EDGE_NOT_FOUND":          agent.CodeServerRoute,
		"E_EDGE_METHOD_NOT_ALLOWED": agent.CodeServerRoute,
		"E_BODY_TOO_LARGE":          agent.CodeServerRoute,
		"E_EDGE_RATE_LIMITED":       agent.CodeRateLimited,
	}
	cases := map[string]struct {
		reply reply
		want  agent.Code
	}{
		"an unknown id under 404":     {reply{http.StatusNotFound, `{"success":false,"message":"x","code":"E_SOMETHING_ELSE"}`}, agent.CodeRoomUnknown},
		"an edge id under its status": {reply{http.StatusNotFound, apperr.EdgeAnswers[0].Body()}, agent.CodeServerAnswer},
		"the outage id under 502":     {reply{http.StatusBadGateway, apperr.EdgeAnswers[0].Body()}, agent.CodeServerBusy},
		"the outage id under 504":     {reply{http.StatusGatewayTimeout, apperr.EdgeAnswers[0].Body()}, agent.CodeServerBusy},
		"a route id under 500":        {reply{http.StatusInternalServerError, apperr.EdgeAnswers[1].Body()}, agent.CodeServerBusy},
	}
	for _, edge := range apperr.EdgeAnswers {
		code, known := want[edge.ID]
		if !known {
			t.Fatalf("nginx answers %s, which this test does not expect: decide what the agent makes of it", edge.ID)
		}
		cases[edge.ID] = struct {
			reply reply
			want  agent.Code
		}{reply{edge.Status, edge.Body()}, code}
	}
	if cases["an edge id under its status"].reply.status == apperr.EdgeAnswers[0].Status {
		t.Fatal("the mismatched case serves the edge id under its own status")
	}
	for name, c := range cases {
		next.Store(&c.reply)
		if _, err := robot.Read(ctx, room, &first.LastSeq); agent.CodeOf(err) != c.want {
			t.Fatalf("%s: %v, want %s", name, err, c.want)
		}
		if after := agentRead(t, robot, room, &first.LastSeq); len(after.Messages)+len(after.Replays) != 0 {
			t.Fatalf("%s: the next read = %+v", name, after)
		}
	}
	carol.say(t, "again", 1)
	again, err := robot.Read(ctx, room, &first.LastSeq)
	if err != nil || len(again.Messages) != 0 || len(again.Replays) != 1 {
		t.Fatalf("after the edge answers an old counter was not a replay: %+v, %v", again, err)
	}
}

// The drill's database pause: PostgreSQL stops answering under a running server. The server
// answers 503 E_STORE_UNAVAILABLE, and the agent must say "temporarily unavailable, retry",
// both on a call with a live session and in a new process whose first step is the login.
func TestAgent_ADatabaseOutageIsAPassingFailure(t *testing.T) {
	mux := setup(t)
	srv := clientServer(t, mux)
	ctx := context.Background()
	path := newIdentityPath(t.TempDir(), "robot")
	robot := newAgent(t, srv.URL, path)
	agentIdentity(t, robot, true)

	restore := breakDatabase(t)
	if _, err := robot.Rooms(ctx); agent.CodeOf(err) != agent.CodeServerBusy {
		t.Fatalf("an authenticated call during the outage: %v, want %s", err, agent.CodeServerBusy)
	}
	robot.Close()
	restarted := newAgent(t, "", path)
	if _, err := restarted.Rooms(ctx); agent.CodeOf(err) != agent.CodeServerBusy {
		t.Fatalf("the login of a new process during the outage: %v, want %s", err, agent.CodeServerBusy)
	}

	restore()
	if _, err := restarted.Rooms(ctx); err != nil {
		t.Fatalf("Rooms after the outage: %v", err)
	}
}

// agentStartWarnings starts a writable agent on path (no network), closes it, and returns how
// many E_AGENT_STATE_REBUILT lines it logged.
func agentStartWarnings(t *testing.T, path string) int {
	t.Helper()
	t.Setenv("LOG_LEVEL", "warn")
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	newAgent(t, "", path).Close()
	log.SetOutput(previous)
	return strings.Count(buf.String(), string(agent.CodeStateRebuilt))
}

// A fresh identity has its counter file from the start, so a restart before any message is sent
// logs nothing; a counter file deleted between runs is reported once and written again.
func TestAgent_ARestartReportsOnlyALostCounterFile(t *testing.T) {
	srv := clientServer(t, setup(t))
	path := newIdentityPath(t.TempDir(), "robot")
	robot := newAgent(t, srv.URL, path)
	agentIdentity(t, robot, true)
	if _, err := robot.Rooms(context.Background()); err != nil {
		t.Fatalf("Rooms: %v", err)
	}
	robot.Close()

	if got := agentStartWarnings(t, path); got != 0 {
		t.Fatalf("a restart of a fresh identity logged E_AGENT_STATE_REBUILT %d times", got)
	}
	if err := os.Remove(agentCounterFile(path)); err != nil {
		t.Fatalf("remove the counter file: %v", err)
	}
	if got := agentStartWarnings(t, path); got != 1 {
		t.Fatalf("a lost counter file was reported %d times, want once", got)
	}
	info, err := os.Stat(agentCounterFile(path))
	if err != nil {
		t.Fatalf("the lost counter file was not written again: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the rewritten counter file has mode %v, want 0600", info.Mode().Perm())
	}
	if got := agentStartWarnings(t, path); got != 0 {
		t.Fatalf("the start after the rewrite logged E_AGENT_STATE_REBUILT %d times", got)
	}
}
