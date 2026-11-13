package integration

// Negative use of the agent program (elyrn-agent): the real agent against the real server over
// real HTTP, and the real MCP layer over real pipes. Tools called before an identity exists,
// against another agent's room, after leaving, after a burn, after the room expired, with a
// cursor from another room, a wait cancelled and the agent reused, a second call while one
// runs, the identity file swapped under a running agent, and tool names and argument shapes
// that almost match. Every failure is the exact registered agent code.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/database"
	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

const (
	// waitCancelAfter lets a wait reach its stream before it is cancelled
	waitCancelAfter = 300 * time.Millisecond
	// negativeRoomMembers and negativeRoomTTLHours are the rooms the agents create here
	negativeRoomMembers  = 4
	negativeRoomTTLHours = 24
	// pastHours puts a code's expiry this many hours behind now
	pastHours = 2
	// jsonRPCInvalidParams is JSON-RPC 2.0's number for an unknown tool or malformed params
	jsonRPCInvalidParams = -32602
)

// agentCall is one call of the agent's API with the code it must fail with.
type agentCall struct {
	name string
	call func() error
	want agent.Code
}

func expectAgentCodes(t *testing.T, calls []agentCall, when string) {
	t.Helper()
	for _, c := range calls {
		if got := agent.CodeOf(c.call()); got != c.want {
			t.Fatalf("%s, %s: %s, want %s", when, c.name, got, c.want)
		}
	}
}

// roomCalls are every room-scoped call of the agent on room, each to fail with want.
func roomCalls(a *agent.Agent, room uuid.UUID, want agent.Code) []agentCall {
	ctx := context.Background()
	return []agentCall{
		{"read", func() error { _, err := a.Read(ctx, room, nil); return err }, want},
		{"read history", func() error { _, err := a.ReadBefore(ctx, room, 1); return err }, want},
		{"send", func() error { _, err := a.Send(ctx, room, "hello"); return err }, want},
		{"members", func() error { _, err := a.Members(ctx, room); return err }, want},
		{"wait", func() error { _, err := a.Wait(ctx, room, 0, agent.MinWaitTimeout); return err }, want},
		{"leave", func() error { _, err := a.Leave(ctx, room); return err }, want},
	}
}

// expiredCodeText is a well-formed room code whose expiry has passed.
func expiredCodeText(t *testing.T) string {
	t.Helper()
	code := &e2e.RoomCode{Secret: randomBytes(t, e2e.RoomSecretSize), MaxMembers: negativeRoomMembers,
		ExpiresHour: uint32(time.Now().Unix()/3600) - pastHours}
	return code.String()
}

// expectNoIdentity insists no account and no identity file exist yet.
func expectNoIdentity(t *testing.T, path, what string) {
	t.Helper()
	expectRows(t, &models.User{}, 0, what)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("%s: the identity file exists (%v)", what, err)
	}
}

// Without an identity and without a server, every call that needs the server says so, and
// every call whose input is wrong says that first; nothing is created.
func TestNegativeAgent_NoIdentityAndNoServer(t *testing.T) {
	setup(t)
	path := newIdentityPath(t.TempDir(), "nobody")
	a := newAgent(t, "", path)
	ctx := context.Background()
	room := uuid.New()
	calls := append(roomCalls(a, room, agent.CodeServerMissing),
		agentCall{"whoami", func() error { _, err := a.Whoami(); return err }, agent.CodeIdentityMissing},
		agentCall{"identity", func() error { _, err := a.Identity(ctx); return err }, agent.CodeServerMissing},
		agentCall{"rooms", func() error { _, err := a.Rooms(ctx); return err }, agent.CodeServerMissing},
		agentCall{"create", func() error { _, err := a.CreateRoom(ctx, negativeRoomMembers, negativeRoomTTLHours); return err }, agent.CodeServerMissing},
		agentCall{"join with a good code", func() error {
			_, err := a.JoinRoom(ctx, newCode(t, negativeRoomMembers, negativeRoomTTLHours).String())
			return err
		}, agent.CodeServerMissing},
		agentCall{"join with a malformed code", func() error { _, err := a.JoinRoom(ctx, "nonsense"); return err }, agent.CodeRoomCode},
		agentCall{"history below the first seq", func() error { _, err := a.ReadBefore(ctx, room, 0); return err }, agent.CodeArgument},
		agentCall{"send an empty text", func() error { _, err := a.Send(ctx, room, ""); return err }, agent.CodeMessageText},
	)
	expectAgentCodes(t, calls, "no identity, no server")
	expectNoIdentity(t, path, "no identity, no server")
}

// With a server but no identity yet, a malformed request is refused before anything is spent:
// no account is created for it (the join's code is judged before the session, a product fix of
// this pass). Any well-formed call creates the identity on first use, as designed, and then
// finds no such room.
func TestNegativeAgent_NothingIsSpentOnAMalformedFirstCall(t *testing.T) {
	srv := clientServer(t, setup(t))
	path := newIdentityPath(t.TempDir(), "first")
	a := newAgent(t, srv.URL, path)
	ctx := context.Background()
	room := uuid.New()
	expectAgentCodes(t, []agentCall{
		{"join with a code of the wrong length", func() error { _, err := a.JoinRoom(ctx, e2e.RoomCodePrefix+"AAAA"); return err }, agent.CodeRoomCode},
		{"join with an expired code", func() error { _, err := a.JoinRoom(ctx, expiredCodeText(t)); return err }, agent.CodeRoomExpired},
		{"send only blanks", func() error { _, err := a.Send(ctx, room, "   "); return err }, agent.CodeMessageText},
		{"wait after a negative seq", func() error { _, err := a.Wait(ctx, room, -1, agent.MinWaitTimeout); return err }, agent.CodeArgument},
		{"wait without a timeout", func() error { _, err := a.Wait(ctx, room, 0, 0); return err }, agent.CodeArgument},
	}, "server, no identity")
	expectNoIdentity(t, path, "malformed first calls")

	if _, err := a.Read(ctx, room, nil); agent.CodeOf(err) != agent.CodeRoomUnknown {
		t.Fatalf("a first read of an unknown room: %v, want %s", err, agent.CodeRoomUnknown)
	}
	expectRows(t, &models.User{}, 1, "the first well-formed call created the identity")
}

// Another agent's room, a room left, a room burned and a room expired are all no room of this
// agent's: every room call answers E_AGENT_ROOM_UNKNOWN and changes nothing. A cursor from
// another room reads nothing of that room.
func TestNegativeAgent_RoomsThatAreNotItsOwn(t *testing.T) {
	mux := setup(t)
	ctx := context.Background()
	dir := t.TempDir()
	alpha := newAgent(t, clientServer(t, mux).URL, newIdentityPath(dir, "alpha"))
	beta := newAgent(t, clientServer(t, mux).URL, newIdentityPath(dir, "beta"))
	created, err := alpha.CreateRoom(ctx, negativeRoomMembers, negativeRoomTTLHours)
	if err != nil {
		t.Fatalf("alpha CreateRoom: %v", err)
	}
	room := uuid.MustParse(created.Room)
	agentSend(t, alpha, room, "alpha only")
	own, err := beta.CreateRoom(ctx, negativeRoomMembers, negativeRoomTTLHours)
	if err != nil {
		t.Fatalf("beta CreateRoom: %v", err)
	}
	ownRoom := uuid.MustParse(own.Room)

	before := countRows(t)
	expectAgentCodes(t, roomCalls(beta, room, agent.CodeRoomUnknown), "another agent's room")
	expectRowsUnchanged(t, before, "calls on another agent's room")

	if _, err := beta.JoinRoom(ctx, created.Code); err != nil {
		t.Fatalf("beta JoinRoom: %v", err)
	}
	if left, err := beta.Leave(ctx, room); err != nil || left.Burned {
		t.Fatalf("beta Leave = %+v, %v", left, err)
	}
	before = countRows(t)
	expectAgentCodes(t, roomCalls(beta, room, agent.CodeRoomUnknown), "a room left")
	expectRowsUnchanged(t, before, "calls on a room left")

	// A cursor from another room: alpha's room is at seq 3, beta's own at seq 1
	agentSend(t, alpha, room, "two")
	alphaLast := agentSend(t, alpha, room, "three")
	agentSend(t, beta, ownRoom, "beta's own")
	if got, err := beta.Read(ctx, ownRoom, &alphaLast); err != nil || len(got.Messages) != 0 {
		t.Fatalf("a read after another room's last seq = %+v, %v", got, err)
	}
	history, err := beta.ReadBefore(ctx, ownRoom, alphaLast+1)
	if err != nil || !slices.Equal(texts(history), []string{"beta's own"}) {
		t.Fatalf("history below another room's cursor = %+v, %v", history, err)
	}

	// A room burned while beta holds it
	if _, err := beta.JoinRoom(ctx, created.Code); err != nil {
		t.Fatalf("beta rejoins: %v", err)
	}
	if left, err := alpha.Leave(ctx, room); err != nil || !left.Burned {
		t.Fatalf("alpha burns = %+v, %v", left, err)
	}
	expectAgentCodes(t, roomCalls(beta, room, agent.CodeRoomUnknown), "a burned room")
	var burned int64
	database.DB.Model(&models.Message{}).Where("conversation_id = ?", room).Count(&burned)
	if burned != 0 {
		t.Fatalf("%d messages outlived the burn", burned)
	}

	// Beta's own room, expired on the server while beta still holds it
	database.DB.Model(&models.Room{}).Where("id = ?", ownRoom).UpdateColumn("expires_at", time.Now().UTC().Add(-time.Second))
	before = countRows(t)
	expectAgentCodes(t, []agentCall{
		{"send to an expired room", func() error { _, err := beta.Send(ctx, ownRoom, "too late"); return err }, agent.CodeRoomUnknown},
		{"read an expired room", func() error { _, err := beta.Read(ctx, ownRoom, nil); return err }, agent.CodeRoomUnknown},
	}, "an expired room")
	expectRowsUnchanged(t, before, "calls on an expired room")
}

// A wait cancelled by its caller ends with E_AGENT_NETWORK, and the same agent serves the next
// wait as if nothing happened.
func TestNegativeAgent_AWaitCancelledThenReused(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := robot.Wait(ctx, room, 0, agent.MaxWaitTimeout)
		done <- err
	}()
	time.Sleep(waitCancelAfter)
	cancel()
	select {
	case err := <-done:
		if agent.CodeOf(err) != agent.CodeNetwork {
			t.Fatalf("a cancelled wait: %v, want %s", err, agent.CodeNetwork)
		}
	case <-time.After(agentWait):
		t.Fatal("a cancelled wait did not end")
	}

	waited := make(chan *agent.ReadResult, 1)
	go func() {
		got, err := robot.Wait(context.Background(), room, 0, agentWait)
		if err != nil {
			got = nil
		}
		waited <- got
	}()
	carol.say(t, "wake up", 1)
	if got := <-waited; got == nil || got.TimedOut || !slices.Equal(texts(got), []string{"wake up"}) {
		t.Fatalf("the wait after a cancelled one = %+v", got)
	}
}

// While a real wait runs, a second tool call is refused with E_AGENT_CALL_IN_FLIGHT whatever it
// names: another agent's room, or arguments that are wrong (the slot is judged first).
func TestNegativeAgent_ASecondCallWhileOneRuns(t *testing.T) {
	s := mcpWaiting(t)
	for id, call := range map[int]string{
		2: fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"room_read","arguments":{"room":%q}}}`, uuid.NewString()),
		3: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"room_send","arguments":{"room":"x"}}}`,
	} {
		s.send(call)
		if r := s.result(s.next(), id); !inFlight(r) {
			t.Fatalf("call %d while a wait runs: %+v, want %s", id, r, agent.CodeCallInFlight)
		}
	}
	s.closeAndExpectEnd()
}

// An identity file swapped for another agent's under a running agent changes nothing for it:
// the identity is read once, at start, and the agent goes on as itself. The next start is the
// file's identity.
func TestNegativeAgent_IdentityFileSwappedWhileRunning(t *testing.T) {
	mux := setup(t)
	ctx := context.Background()
	dir := t.TempDir()
	alphaPath, betaPath := newIdentityPath(dir, "alpha"), newIdentityPath(dir, "beta")
	alpha := newAgent(t, clientServer(t, mux).URL, alphaPath)
	beta := newAgent(t, clientServer(t, mux).URL, betaPath)
	alphaRoom, err := alpha.CreateRoom(ctx, negativeRoomMembers, negativeRoomTTLHours)
	if err != nil {
		t.Fatalf("alpha CreateRoom: %v", err)
	}
	betaRoom, err := beta.CreateRoom(ctx, negativeRoomMembers, negativeRoomTTLHours)
	if err != nil {
		t.Fatalf("beta CreateRoom: %v", err)
	}
	alphaWho, err := alpha.Whoami()
	if err != nil {
		t.Fatalf("alpha Whoami: %v", err)
	}
	betaWho, err := beta.Whoami()
	if err != nil {
		t.Fatalf("beta Whoami: %v", err)
	}
	betaFile, err := os.ReadFile(betaPath)
	if err != nil {
		t.Fatalf("read beta's identity: %v", err)
	}
	if err := os.WriteFile(alphaPath, betaFile, 0o600); err != nil {
		t.Fatalf("swap the identity file: %v", err)
	}

	if who, err := alpha.Whoami(); err != nil || who.PublicKey != alphaWho.PublicKey {
		t.Fatalf("the running agent's identity after the swap = %+v, %v", who, err)
	}
	listed, err := alpha.Rooms(ctx)
	if err != nil || len(listed.Rooms) != 1 || listed.Rooms[0].Room != alphaRoom.Room {
		t.Fatalf("the running agent's rooms after the swap = %+v, %v", listed, err)
	}
	agentSend(t, alpha, uuid.MustParse(alphaRoom.Room), "still alpha")

	alpha.Close()
	beta.Close()
	restarted := newAgent(t, "", alphaPath)
	if who, err := restarted.Whoami(); err != nil || who.PublicKey != betaWho.PublicKey {
		t.Fatalf("the restarted agent = %+v, %v, want the swapped-in identity", who, err)
	}
	if listed, err := restarted.Rooms(ctx); err != nil || len(listed.Rooms) != 1 || listed.Rooms[0].Room != betaRoom.Room {
		t.Fatalf("the restarted agent's rooms = %+v, %v", listed, err)
	}
}

// mcpLine is any line the MCP server writes: a result, or an error with its registered code.
type mcpLine struct {
	ID     json.RawMessage `json:"id"`
	Result *mcpToolResult  `json:"result"`
	Error  *struct {
		Code int `json:"code"`
		Data struct {
			Code agent.Code `json:"code"`
		} `json:"data"`
	} `json:"error"`
}

// nextLine reads the next line of s as an mcpLine.
func (s *mcpSession) nextLine() mcpLine {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatal("stdout closed before an answer")
		}
		var l mcpLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			s.t.Fatalf("not a JSON-RPC line on stdout: %q (%v)", line, err)
		}
		return l
	case <-time.After(mcpTimeout):
		s.t.Fatal("no answer in time")
	}
	return mcpLine{}
}

// toolErrorCode is the registered code of a tool result that is an error ("" otherwise).
func toolErrorCode(r *mcpToolResult) agent.Code {
	if r == nil || !r.IsError || len(r.Content) != 1 {
		return ""
	}
	var body struct {
		Error struct {
			Code agent.Code `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(r.Content[0].Text), &body); err != nil {
		return ""
	}
	return body.Error.Code
}

// TestNegativeAgent_NearlyRightToolsAndArguments: tool names one character off, and arguments of
// a near shape (a wrong case, an unknown name, a wrong type, a fraction, a negative, a bound
// crossed, an array for the object) are refused with their exact code, before the agent touches
// the server: no identity comes into being for any of them.
func TestNegativeAgent_NearlyRightToolsAndArguments(t *testing.T) {
	srv := clientServer(t, setup(t))
	path := newIdentityPath(t.TempDir(), "robot")
	s := startMCP(t, newAgent(t, srv.URL, path))
	room := uuid.NewString()
	call := func(id int, name, arguments string) string {
		quoted, err := json.Marshal(name)
		if err != nil {
			t.Fatalf("marshal a tool name: %v", err)
		}
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%s,"arguments":%s}}`, id, quoted, arguments)
	}
	roomArg := fmt.Sprintf(`{"room":%q}`, room)

	names := []string{"Rooms", "rooms ", "room-read", "room_reads", "roomread", "identity\u0000", "tools/list"}
	id := 0
	for _, name := range names {
		id++
		s.send(call(id, name, "{}"))
		l := s.nextLine()
		if l.Error == nil || l.Error.Code != jsonRPCInvalidParams || l.Error.Data.Code != agent.CodeUnknownTool {
			t.Fatalf("tool %q: %+v, want %s", name, l, agent.CodeUnknownTool)
		}
	}
	id++
	s.send(call(id, "", "{}"))
	if l := s.nextLine(); l.Error == nil || l.Error.Data.Code != agent.CodeRPCParams {
		t.Fatalf("an empty tool name: %+v, want %s", l, agent.CodeRPCParams)
	}

	args := []struct {
		tool, arguments string
		want            agent.Code
	}{
		{"room_read", fmt.Sprintf(`{"room":%q}`, "A"+room[1:]), agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room_id":%q}`, room), agent.CodeArgument},
		{"room_read", `{"room":7}`, agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room":%q,"after":"1"}`, room), agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room":%q,"after":1.5}`, room), agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room":%q,"after":-1}`, room), agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room":%q,"before":0}`, room), agent.CodeArgument},
		{"room_read", fmt.Sprintf(`{"room":%q,"after":1,"before":2}`, room), agent.CodeArgument},
		{"room_read", `[]`, agent.CodeArgument},
		{"room_members", `{}`, agent.CodeArgument},
		{"room_wait", fmt.Sprintf(`{"room":%q,"after":0,"timeout_seconds":0}`, room), agent.CodeArgument},
		{"room_send", roomArg, agent.CodeArgument},
		{"room_send", fmt.Sprintf(`{"room":%q,"text":"   "}`, room), agent.CodeMessageText},
		{"room_create", `{"max_members":1,"ttl_hours":24}`, agent.CodeArgument},
		{"room_create", `{"max_members":4,"ttl_hours":0}`, agent.CodeArgument},
		{"room_create", `{"max_members":4}`, agent.CodeArgument},
		{"room_join", `{"code":"a room code"}`, agent.CodeRoomCode},
		{"room_join", fmt.Sprintf(`{"code":%q}`, e2e.RoomCodePrefix+"AAAA"), agent.CodeRoomCode},
		{"room_join", fmt.Sprintf(`{"code":%q}`, expiredCodeText(t)), agent.CodeRoomExpired},
		{"rooms", `{"room":"x"}`, agent.CodeArgument},
		{"identity", `{"create":true}`, agent.CodeArgument},
	}
	for _, c := range args {
		id++
		s.send(call(id, c.tool, c.arguments))
		l := s.nextLine()
		if got := toolErrorCode(l.Result); l.Error != nil || got != c.want {
			t.Fatalf("%s %s: %+v (%s), want %s", c.tool, c.arguments, l, got, c.want)
		}
	}
	s.closeAndExpectEnd()
	expectNoIdentity(t, path, "nearly right calls")
}
