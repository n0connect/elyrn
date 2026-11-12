package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"elyrn/internal/agent"
	"elyrn/internal/utils"
)

var logger = utils.NewLogger("MCP")

// Server answers one MCP client on one pair of streams. Requests are handled one at a time, in
// order; a long room_wait therefore delays the next answer (at most agent.MaxWaitTimeout).
type Server struct {
	backend Backend
	out     io.Writer
}

// Serve reads newline-delimited JSON-RPC from in and writes answers to out until in ends.
func Serve(ctx context.Context, in io.Reader, out io.Writer, backend Backend) error {
	s := &Server{backend: backend, out: out}
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
	_, err = s.out.Write(append(raw, '\n'))
	return err
}

// handle turns one line into its answer, or nil for a notification. It never panics on input:
// a panic below is recovered into an internal error.
func (s *Server) handle(ctx context.Context, raw []byte) (resp *response) {
	id := nullID
	defer func() {
		if recovered := recover(); recovered != nil {
			logger.Error("a request panicked and was answered with an internal error")
			resp = errorResponse(id, agent.CodeRPCInternal)
		}
	}()
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
	result, err := s.dispatch(ctx, &req)
	if err != nil {
		return errorResponse(id, agent.CodeOf(err))
	}
	return &response{JSONRPC: jsonrpcVersion, ID: id, Result: result}
}

// notify handles a notification; none is ever answered.
func (s *Server) notify(req *request) {
	switch req.Method {
	case NotifyInitialized, NotifyCancelled:
		logger.Debug("notification received")
	default:
		logger.Debug("unknown notification ignored")
	}
}

func (s *Server) dispatch(ctx context.Context, req *request) (any, error) {
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
	case MethodToolsCall:
		return s.callTool(ctx, req.Params)
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
