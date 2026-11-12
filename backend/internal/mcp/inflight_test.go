package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"elyrn/internal/agent"

	"github.com/google/uuid"
)

// These tests drive Serve over real operating-system pipes, as an MCP client does. The backend
// is a minimal real implementation of Backend: its Wait blocks until its context ends, which is
// exactly the behaviour under test; every other method refuses.

const pipeTimeout = 5 * time.Second

type waitingBackend struct {
	entered  chan struct{} // closed when Wait starts
	released chan struct{} // closed when Wait has seen its context end
}

func newWaitingBackend() *waitingBackend {
	return &waitingBackend{entered: make(chan struct{}), released: make(chan struct{})}
}

func (b *waitingBackend) Wait(ctx context.Context, _ uuid.UUID, _ int64, _ time.Duration) (*agent.ReadResult, error) {
	close(b.entered)
	<-ctx.Done()
	close(b.released)
	return nil, agent.Fail(agent.CodeNetwork, ctx.Err())
}

func refused() error { return agent.Fail(agent.CodeInternal, nil) }

func (b *waitingBackend) Identity(context.Context) (*agent.IdentityResult, error) {
	return nil, refused()
}
func (b *waitingBackend) CreateRoom(context.Context, int, int) (*agent.RoomCreated, error) {
	return nil, refused()
}
func (b *waitingBackend) JoinRoom(context.Context, string) (*agent.RoomJoined, error) {
	return nil, refused()
}
func (b *waitingBackend) Rooms(context.Context) (*agent.RoomsResult, error) { return nil, refused() }
func (b *waitingBackend) Members(context.Context, uuid.UUID) (*agent.MembersResult, error) {
	return nil, refused()
}
func (b *waitingBackend) Send(context.Context, uuid.UUID, string) (*agent.Sent, error) {
	return nil, refused()
}
func (b *waitingBackend) Read(context.Context, uuid.UUID, *int64) (*agent.ReadResult, error) {
	return nil, refused()
}
func (b *waitingBackend) Leave(context.Context, uuid.UUID) (*agent.Left, error) {
	return nil, refused()
}

// session is one Serve over two pipes: the test writes stdin and reads stdout line by line.
type session struct {
	t      *testing.T
	stdin  *os.File
	lines  chan string
	served chan error
}

func startSession(t *testing.T, backend Backend) *session {
	t.Helper()
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	s := &session{t: t, stdin: inWrite, lines: make(chan string, 16), served: make(chan error, 1)}
	go func() {
		s.served <- Serve(context.Background(), inRead, outWrite, backend)
		_ = outWrite.Close()
	}()
	go func() {
		defer close(s.lines)
		scanner := bufio.NewScanner(outRead)
		for scanner.Scan() {
			s.lines <- scanner.Text()
		}
	}()
	t.Cleanup(func() {
		_ = inWrite.Close()
		_ = inRead.Close()
		_ = outRead.Close()
	})
	return s
}

func (s *session) send(line string) {
	s.t.Helper()
	if _, err := s.stdin.WriteString(line + "\n"); err != nil {
		s.t.Fatalf("write stdin: %v", err)
	}
}

func (s *session) next() answer {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatal("stdout closed before an answer")
		}
		var a answer
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.JSONRPC != jsonrpcVersion {
			s.t.Fatalf("not a JSON-RPC line on stdout: %q (%v)", line, err)
		}
		return a
	case <-time.After(pipeTimeout):
		s.t.Fatal("no answer in time")
	}
	return answer{}
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(pipeTimeout):
		t.Fatalf("%s did not happen in time", what)
	}
}

const waitCall = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"room_wait","arguments":{"room":` +
	validRoom + `,"after":0,"timeout_seconds":300}}}`

func TestServe_PingIsAnsweredWhileAWaitRuns(t *testing.T) {
	backend := newWaitingBackend()
	s := startSession(t, backend)
	s.send(waitCall)
	waitFor(t, backend.entered, "the wait")
	s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	expectResult(t, s.next(), "2")
	s.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rooms"}}`)
	busy := s.next()
	expectResult(t, busy, "3")
	var result toolResult
	if err := json.Unmarshal(busy.Result, &result); err != nil || !result.IsError || len(result.Content) != 1 ||
		!strings.Contains(result.Content[0].Text, string(agent.CodeCallInFlight)) {
		t.Fatalf("a second call must be refused with %s, got %s", agent.CodeCallInFlight, busy.Result)
	}
	_ = s.stdin.Close()
	waitFor(t, backend.released, "the wait's end on stdin close")
	select {
	case err := <-s.served:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(pipeTimeout):
		t.Fatal("Serve did not return after stdin closed")
	}
}

func TestServe_CancelledWaitEndsAndIsNotAnswered(t *testing.T) {
	backend := newWaitingBackend()
	s := startSession(t, backend)
	s.send(waitCall)
	waitFor(t, backend.entered, "the wait")
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"1"}}`) // another id
	s.send(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	expectResult(t, s.next(), "2")
	select {
	case <-backend.released:
		t.Fatal("a cancellation for another id ended the wait")
	default:
	}
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1,"reason":"user"}}`)
	waitFor(t, backend.released, "the cancelled wait's end")
	s.send(`{"jsonrpc":"2.0","id":4,"method":"ping"}`)
	expectResult(t, s.next(), "4") // the cancelled call 1 was not answered before it
	// The slot frees just after the wait returns, so a call may still meet it busy for a moment;
	// the cancelled call 1 must never be answered meanwhile.
	const freeAttempts = 50
	free := false
	for attempt := 0; attempt < freeAttempts && !free; attempt++ {
		s.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"rooms"}}`)
		a := s.next()
		if string(a.ID) != "5" {
			t.Fatalf("an answer for id %s arrived; only id 5 was pending", a.ID)
		}
		free = !strings.Contains(string(a.Result), string(agent.CodeCallInFlight))
		if !free {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if !free {
		t.Fatal("the slot stayed busy after the cancelled call ended")
	}
	_ = s.stdin.Close()
	select {
	case <-s.served:
	case <-time.After(pipeTimeout):
		t.Fatal("Serve did not return after stdin closed")
	}
}

func TestCanonicalID(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{`7`, `7`, true}, {`7`, `"7"`, false}, {`"a"`, `"a"`, true}, {`-1`, `-1`, true}, {`"x"`, `"y"`, false},
	} {
		if got := canonicalID(json.RawMessage(tc.a)) == canonicalID(json.RawMessage(tc.b)); got != tc.same {
			t.Errorf("canonicalID(%s) == canonicalID(%s) is %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
