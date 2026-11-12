package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/e2e"

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

// agentReloads starts alpha again from its identity file: private permissions, the same
// identity through a fresh login, and refusal of another server or wider permissions.
func agentReloads(t *testing.T, server, path string) {
	t.Helper()
	for p, want := range map[string]os.FileMode{path: 0o600, filepath.Dir(path): 0o700} {
		info, err := os.Stat(p)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v, %v (want %v)", filepath.Base(p), info.Mode().Perm(), err, want)
		}
	}
	first := newAgent(t, "", path)
	who, err := first.Whoami()
	if err != nil || who.Server != server {
		t.Fatalf("Whoami = %+v, %v", who, err)
	}
	if again := agentIdentity(t, first, false); again.PublicKey != who.PublicKey || again.Name != who.Name {
		t.Fatalf("the reloaded identity differs: %+v vs %+v", again, who)
	}
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
