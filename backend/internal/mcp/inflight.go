package mcp

import (
	"context"
	"encoding/json"
	"strconv"

	"elyrn/internal/agent"
)

// One tool call at a time runs beside the reader. Keeping it to one keeps the agent simple (its
// calls are serialized anyway) and bounds the goroutines to two: the reader and this one.

const (
	idKindString = "s:"
	idKindNumber = "n:"
)

// call is the tool call in flight.
type call struct {
	id     string // canonicalID of its request
	cancel context.CancelFunc
}

type cancelledParams struct {
	RequestID json.RawMessage `json:"requestId"`
	Reason    *string         `json:"reason"`
	Meta      json.RawMessage `json:"_meta"`
}

// startCall validates a tools/call on the reader's goroutine, so malformed calls are answered in
// order, and starts the tool on its own goroutine. nil means the answer comes later from there.
func (s *Server) startCall(ctx context.Context, id, params json.RawMessage) *response {
	t, args, err := prepareCall(params)
	if err != nil {
		return answerFor(id, nil, err)
	}
	callCtx, cancel := context.WithCancel(ctx)
	c := &call{id: canonicalID(id), cancel: cancel}
	if !s.inflight.CompareAndSwap(nil, c) {
		cancel()
		result, err := toolError(agent.CodeCallInFlight)
		return answerFor(id, result, err)
	}
	s.calls.Add(1)
	go s.runCall(callCtx, c, id, t, args)
	return nil
}

// runCall runs the tool and writes its answer, unless the call was cancelled (by
// notifications/cancelled, or because stdin ended): a cancelled request is never answered.
func (s *Server) runCall(ctx context.Context, c *call, id json.RawMessage, t *tool, args json.RawMessage) {
	defer s.calls.Done()
	defer c.cancel()
	resp := s.callAnswer(ctx, id, t, args)
	s.inflight.CompareAndSwap(c, nil)
	if ctx.Err() != nil {
		logger.Debug("a cancelled tool call is not answered")
		return
	}
	if err := s.write(resp); err != nil {
		logger.Warn("a tool answer could not be written")
	}
}

// callAnswer is the answer of one tool run; a panic in the tool becomes an internal error.
func (s *Server) callAnswer(ctx context.Context, id json.RawMessage, t *tool, args json.RawMessage) (resp *response) {
	defer recoverInto(&id, &resp)
	result, err := runTool(ctx, s.backend, t, args)
	return answerFor(id, result, err)
}

// cancel honours notifications/cancelled for the call in flight. Any other id is ignored, as
// the MCP specification asks for a request that is unknown or already answered.
func (s *Server) cancel(raw json.RawMessage) {
	var params cancelledParams
	if err := decodeParams(raw, &params, agent.CodeRPCParams); err != nil || !validID(params.RequestID) {
		logger.Debug("a malformed cancellation was ignored")
		return
	}
	if c := s.inflight.Load(); c != nil && c.id == canonicalID(params.RequestID) {
		c.cancel()
		logger.Info("the tool call in flight was cancelled")
		return
	}
	logger.Debug("a cancellation for no call in flight was ignored")
}

// canonicalID spells each request id one way, so 7 and "7" differ while "a" and "a" match.
// The id has passed validID.
func canonicalID(raw json.RawMessage) string {
	if len(raw) > 0 && raw[0] == '"' {
		var id string
		if err := json.Unmarshal(raw, &id); err != nil {
			return ""
		}
		return idKindString + id
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return ""
	}
	return idKindNumber + strconv.FormatInt(n, 10)
}
