package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/mcp"

	"github.com/google/uuid"
)

// The MCP layer as `elyrn-agent serve` runs it: Serve over real operating-system pipes, in front
// of a real agent that talks to the real server over real HTTP. A room_wait here is a real
// event-stream wait on the server; nothing in this file stands in for a component.

const (
	mcpTimeout = 5 * time.Second // far below the wait's own timeout, so an end is never a timeout
	// The tool slot frees just after the cancelled wait returns; poll it a bounded number of times
	mcpFreeAttempts = 50
	mcpFreePause    = 10 * time.Millisecond
	mcpRoomMembers  = 4
	mcpRoomTTLHours = 24
	mcpWaitCallID   = 1
)

type mcpAnswer struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type mcpToolResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

// clientServer serves the real mux over real HTTP as one client address of its own. Robots
// connect from 127.0.0.1, and the PoW budget is per client and outlives a test: each MCP test
// spends its three challenges from a fresh address, never from the agent flow's.
func clientServer(t *testing.T, mux http.Handler) *httptest.Server {
	t.Helper()
	addr := newClient(t, mux).ip
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.RemoteAddr = addr
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mcpSession is one Serve over two pipes: the test writes stdin and reads stdout line by line.
type mcpSession struct {
	t     *testing.T
	stdin *os.File
	lines chan string
	done  chan struct{} // closed when Serve has returned
	err   error         // Serve's result, readable once done is closed
}

func startMCP(t *testing.T, backend mcp.Backend) *mcpSession {
	t.Helper()
	inRead, inWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	outRead, outWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	s := &mcpSession{t: t, stdin: inWrite, lines: make(chan string, 16), done: make(chan struct{})}
	go func() {
		s.err = mcp.Serve(context.Background(), inRead, outWrite, backend)
		close(s.done)
		_ = outWrite.Close()
	}()
	go func() {
		defer close(s.lines)
		scanner := bufio.NewScanner(outRead)
		for scanner.Scan() {
			s.lines <- scanner.Text()
		}
	}()
	// Registered after the server and the agent, so it runs before them: Serve (and with it the
	// real wait) has ended before the agent closes and the HTTP server shuts down
	t.Cleanup(func() {
		_ = inWrite.Close()
		select {
		case <-s.done:
		case <-time.After(mcpTimeout):
			t.Error("Serve did not return at cleanup")
		}
		_ = inRead.Close()
		_ = outRead.Close()
	})
	return s
}

func (s *mcpSession) send(line string) {
	s.t.Helper()
	if _, err := s.stdin.WriteString(line + "\n"); err != nil {
		s.t.Fatalf("write stdin: %v", err)
	}
}

func (s *mcpSession) next() mcpAnswer {
	s.t.Helper()
	select {
	case line, ok := <-s.lines:
		if !ok {
			s.t.Fatal("stdout closed before an answer")
		}
		var a mcpAnswer
		if err := json.Unmarshal([]byte(line), &a); err != nil || a.JSONRPC != "2.0" {
			s.t.Fatalf("not a JSON-RPC line on stdout: %q (%v)", line, err)
		}
		return a
	case <-time.After(mcpTimeout):
		s.t.Fatal("no answer in time")
	}
	return mcpAnswer{}
}

// result insists on a JSON-RPC result for id and returns it as a tool result.
func (s *mcpSession) result(a mcpAnswer, id int) mcpToolResult {
	s.t.Helper()
	if a.Error != nil || a.Result == nil || string(a.ID) != fmt.Sprint(id) {
		s.t.Fatalf("answer %+v (error %+v), want a result for id %d", a, a.Error, id)
	}
	var r mcpToolResult
	if err := json.Unmarshal(a.Result, &r); err != nil {
		s.t.Fatalf("result for id %d is not a tool result: %s", id, a.Result)
	}
	return r
}

// inFlight reports whether a tool result is the refusal of a second concurrent call.
func inFlight(r mcpToolResult) bool {
	return r.IsError && len(r.Content) == 1 && strings.Contains(r.Content[0].Text, string(agent.CodeCallInFlight))
}

// closeAndExpectEnd closes stdin and insists Serve returns cleanly in time. Serve returns only
// after the tool call in flight has ended, so this also proves the real wait ended; whatever is
// left on stdout afterwards would be an answer to a cancelled call, which must not exist.
func (s *mcpSession) closeAndExpectEnd() {
	s.t.Helper()
	_ = s.stdin.Close()
	select {
	case <-s.done:
	case <-time.After(mcpTimeout):
		s.t.Fatal("Serve did not return after stdin closed")
	}
	if s.err != nil {
		s.t.Fatalf("Serve: %v", s.err)
	}
	for line := range s.lines {
		s.t.Fatalf("an answer arrived after the session ended: %s", line)
	}
}

func ping(id int) string { return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"ping"}`, id) }

func roomsCall(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"rooms"}}`, id)
}

func cancelOf(requestID string) string {
	return `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":` + requestID + `,"reason":"user"}}`
}

// mcpWaiting registers a real agent, creates a real room and starts a room_wait for it through
// MCP (id mcpWaitCallID), with nothing to wake it before its 300-second timeout.
func mcpWaiting(t *testing.T) *mcpSession {
	t.Helper()
	ctx := context.Background()
	srv := clientServer(t, setup(t))
	robot := newAgent(t, srv.URL, filepath.Join(t.TempDir(), "agent.json"))
	created, err := robot.CreateRoom(ctx, mcpRoomMembers, mcpRoomTTLHours)
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	caughtUp, err := robot.Read(ctx, uuid.MustParse(created.Room), nil)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	s := startMCP(t, robot)
	s.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"room_wait","arguments":{"room":%q,"after":%d,"timeout_seconds":%d}}}`,
		mcpWaitCallID, created.Room, caughtUp.LastSeq, int(agent.MaxWaitTimeout/time.Second)))
	return s
}

// While a real room_wait runs, the session still answers ping, refuses a second tool call with
// E_AGENT_CALL_IN_FLIGHT, and ends (with the wait, unanswered) when stdin closes.
func TestMCP_PingIsAnsweredWhileARealWaitRuns(t *testing.T) {
	s := mcpWaiting(t)
	s.send(ping(2))
	s.result(s.next(), 2)
	s.send(roomsCall(3))
	if r := s.result(s.next(), 3); !inFlight(r) {
		t.Fatalf("a second call must be refused with %s, got %+v", agent.CodeCallInFlight, r)
	}
	s.closeAndExpectEnd()
}

// notifications/cancelled for another id leaves the real wait running; for its id it ends the
// wait, which is never answered, and frees the slot for the next call.
func TestMCP_CancelEndsTheRealWaitAndFreesTheSlot(t *testing.T) {
	s := mcpWaiting(t)
	s.send(cancelOf(`"1"`)) // a string id: another request than the number 1
	s.send(ping(2))
	s.result(s.next(), 2)
	s.send(roomsCall(3))
	if r := s.result(s.next(), 3); !inFlight(r) {
		t.Fatalf("a cancellation for another id ended the wait: %+v", r)
	}

	s.send(cancelOf(fmt.Sprint(mcpWaitCallID)))
	free := false
	for attempt := 0; attempt < mcpFreeAttempts && !free; attempt++ {
		s.send(roomsCall(5))
		a := s.next()
		if string(a.ID) != "5" {
			t.Fatalf("an answer for id %s arrived; only id 5 was pending", a.ID)
		}
		r := s.result(a, 5)
		free = !inFlight(r)
		if free && r.IsError {
			t.Fatalf("rooms after the cancelled wait failed: %+v", r)
		}
		if !free {
			time.Sleep(mcpFreePause)
		}
	}
	if !free {
		t.Fatal("the slot stayed busy after the cancelled wait")
	}
	s.closeAndExpectEnd()
}
