package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"elyrn/internal/agent"
	"elyrn/internal/utils"
)

var logger = utils.NewLogger("MCP")

// writeLockTimeout bounds the wait for stdout: one line takes microseconds unless the client has
// stopped reading, and then the session is over anyway.
const writeLockTimeout = 30 * time.Second

// Server answers one MCP client on one pair of streams. Lines are read in order on one goroutine,
// which answers initialize, ping and tools/list at once; at most one tools/call runs beside it on
// its own goroutine (inflight.go), so a long room_wait neither freezes the session nor ignores
// notifications/cancelled.
type Server struct {
	backend Backend
	out     io.Writer
	// outLock is the one lock of the MCP layer: it serialises writes to out, so the reader's
	// answers and the tool goroutine's answer never interleave within a line. It is held for one
	// Write only and never while the backend runs, so it never nests with agent.Agent's call
	// lock. A write that cannot get it within writeLockTimeout fails; on the reader that ends
	// the session.
	outLock  *utils.SafeMutex
	inflight atomic.Pointer[call] // the tool call in flight, nil when none
	calls    sync.WaitGroup       // tool goroutines still running
}

// Serve reads newline-delimited JSON-RPC from in and writes answers to out until in ends. It
// returns only after the tool goroutine, if any, has been cancelled and has ended.
func Serve(ctx context.Context, in io.Reader, out io.Writer, backend Backend) error {
	ctx, stop := context.WithCancel(ctx)
	s := &Server{backend: backend, out: out, outLock: utils.NewSafeMutexWithTimeout(writeLockTimeout)}
	defer s.calls.Wait() // deferred first, so it runs after stop
	defer stop()
	reader := bufio.NewReaderSize(in, MaxLineBytes)
	for line := 0; line < maxLines && ctx.Err() == nil; line++ {
		raw, err := agent.ReadBoundedLine(reader)
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, agent.ErrLineTooLong):
			if err := s.write(errorResponse(nullID, agent.CodeRPCParse)); err != nil {
				return err
			}
			continue
		case err != nil:
			return err
		}
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		if resp := s.handle(ctx, raw); resp != nil {
			if err := s.write(resp); err != nil {
				return err
			}
		}
	}
	return nil
}

// write emits one answer as one line: json.Marshal escapes every newline inside strings.
func (s *Server) write(resp *response) error {
	raw, err := json.Marshal(resp)
	if err != nil {
		logger.Error("an answer could not be encoded")
		raw, err = json.Marshal(errorResponse(resp.ID, agent.CodeRPCInternal))
		if err != nil {
			return err
		}
	}
	if err := s.outLock.Lock(); err != nil {
		logger.Error("stdout stayed blocked; the answer is dropped")
		return err
	}
	defer s.outLock.Unlock()
	_, err = s.out.Write(append(raw, '\n'))
	return err
}

// handle turns one line into its answer, or nil for a notification or a tool call now running.
// It never panics on input: a panic below is recovered into an internal error.
func (s *Server) handle(ctx context.Context, raw []byte) (resp *response) {
	id := nullID
	defer recoverInto(&id, &resp)
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return errorResponse(nullID, agent.CodeRPCParse)
	}
	if trimmed := bytes.TrimSpace(raw); trimmed[0] != '{' {
		return errorResponse(nullID, agent.CodeRPCRequest) // batches are not part of MCP
	}
	var req request
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return errorResponse(nullID, agent.CodeRPCRequest)
	}
	if req.ID == nil {
		s.notify(&req)
		return nil
	}
	if !validID(req.ID) {
		return errorResponse(nullID, agent.CodeRPCRequest)
	}
	id = req.ID
	if req.JSONRPC != jsonrpcVersion || !validMethod(req.Method) {
		return errorResponse(id, agent.CodeRPCRequest)
	}
	if req.Method == MethodToolsCall {
		return s.startCall(ctx, id, req.Params)
	}
	result, err := s.dispatch(&req)
	return answerFor(id, result, err)
}

// recoverInto turns a panic of the deferring function into an internal error for *id. It must
// be deferred directly, so that recover sees the panic.
func recoverInto(id *json.RawMessage, resp **response) {
	if recovered := recover(); recovered != nil {
		logger.Error("a request panicked and was answered with an internal error")
		*resp = errorResponse(*id, agent.CodeRPCInternal)
	}
}

// answerFor wraps a method's outcome into the answer for id.
func answerFor(id json.RawMessage, result any, err error) *response {
	if err != nil {
		return errorResponse(id, agent.CodeOf(err))
	}
	return &response{JSONRPC: jsonrpcVersion, ID: id, Result: result}
}

// notify handles a notification; none is ever answered.
func (s *Server) notify(req *request) {
	switch req.Method {
	case NotifyInitialized:
		logger.Debug("notification received")
	case NotifyCancelled:
		s.cancel(req.Params)
	default:
		logger.Debug("unknown notification ignored")
	}
}

// dispatch answers the methods that return at once; tools/call goes through startCall.
func (s *Server) dispatch(req *request) (any, error) {
	switch req.Method {
	case MethodInitialize:
		return initialize(req.Params)
	case MethodPing:
		var params metaOnly
		if err := decodeParams(req.Params, &params, agent.CodeRPCParams); err != nil {
			return nil, err
		}
		return struct{}{}, nil
	case MethodToolsList:
		return listTools(req.Params)
	default:
		return nil, agent.Fail(agent.CodeRPCMethod, nil)
	}
}

func initialize(raw json.RawMessage) (any, error) {
	var params initializeParams
	if err := decodeParams(raw, &params, agent.CodeRPCParams); err != nil {
		return nil, err
	}
	if params.ProtocolVersion == "" || len(params.ProtocolVersion) > maxVersionLen {
		return nil, agent.Fail(agent.CodeRPCParams, nil)
	}
	version := supportedVersions[0]
	for _, supported := range supportedVersions {
		if params.ProtocolVersion == supported {
			version = supported
		}
	}
	return &initializeResult{
		ProtocolVersion: version,
		Capabilities:    capabilities{Tools: toolsCapability{ListChanged: false}},
		ServerInfo:      nameVersion{Name: serverName, Version: serverVersion},
		Instructions:    instructionsForLLM,
	}, nil
}
