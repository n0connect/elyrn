package agent

// The one error home of elyrn-agent (the MCP layer and the command use it too). Every failure
// carries a registered code and a sentence that tells the operator what to do next; neither
// ever contains server text, system text, a path or a secret. The root cause stays reachable
// through errors.Is / errors.As for the program itself.

import (
	"errors"
)

// Code is a registered failure code.
type Code string

const (
	// The MCP conversation itself (JSON-RPC 2.0)
	CodeRPCParse    Code = "E_AGENT_RPC_PARSE"
	CodeRPCRequest  Code = "E_AGENT_RPC_REQUEST"
	CodeRPCMethod   Code = "E_AGENT_RPC_METHOD"
	CodeRPCParams   Code = "E_AGENT_RPC_PARAMS"
	CodeRPCInternal Code = "E_AGENT_RPC_INTERNAL"
	CodeUnknownTool Code = "E_AGENT_UNKNOWN_TOOL"
	CodeArgument    Code = "E_AGENT_ARGUMENT"

	// The command line, the server address and the identity file
	CodeUsage               Code = "E_AGENT_USAGE"
	CodeServerURL           Code = "E_AGENT_SERVER_URL"
	CodeServerMissing       Code = "E_AGENT_SERVER_MISSING"
	CodeServerMismatch      Code = "E_AGENT_SERVER_MISMATCH"
	CodeOnionProxy          Code = "E_AGENT_ONION_PROXY"
	CodeProxy               Code = "E_AGENT_PROXY"
	CodeConfigDir           Code = "E_AGENT_CONFIG_DIR"
	CodeIdentityMissing     Code = "E_AGENT_IDENTITY_MISSING"
	CodeIdentityPermissions Code = "E_AGENT_IDENTITY_PERMISSIONS"
	CodeIdentityFile        Code = "E_AGENT_IDENTITY_FILE"
	CodeIdentityUnknown     Code = "E_AGENT_IDENTITY_UNKNOWN"
	CodeIdentityMismatch    Code = "E_AGENT_IDENTITY_MISMATCH"

	// Talking to the server
	CodeNetwork          Code = "E_AGENT_NETWORK"
	CodeServerAnswer     Code = "E_AGENT_SERVER_ANSWER"
	CodeServerBusy       Code = "E_AGENT_SERVER_BUSY"
	CodeRateLimited      Code = "E_AGENT_RATE_LIMITED"
	CodeUnexpectedStatus Code = "E_AGENT_UNEXPECTED_STATUS"
	CodeProofOfWork      Code = "E_AGENT_POW"
	CodeBusy             Code = "E_AGENT_BUSY"

	// Rooms
	CodeRoomUnknown   Code = "E_AGENT_ROOM_UNKNOWN"
	CodeRoomVerify    Code = "E_AGENT_ROOM_VERIFY"
	CodeRoomCode      Code = "E_AGENT_ROOM_CODE"
	CodeRoomExpired   Code = "E_AGENT_ROOM_EXPIRED"
	CodeRoomNotFound  Code = "E_AGENT_ROOM_NOT_FOUND"
	CodeRoomFull      Code = "E_AGENT_ROOM_FULL"
	CodeRoomLimit     Code = "E_AGENT_ROOM_LIMIT"
	CodeRoomCreate    Code = "E_AGENT_ROOM_CREATE"
	CodeRoster        Code = "E_AGENT_ROSTER"
	CodeRosterChanged Code = "E_AGENT_ROSTER_CHANGED"
	CodeMessageText   Code = "E_AGENT_MESSAGE_TEXT"
	CodeSendUncertain Code = "E_AGENT_SEND_UNCERTAIN"
	CodeInternal      Code = "E_AGENT_INTERNAL"
)

// sentences is the registry: a code without a sentence is a programming error (Sentence falls
// back to the internal one, and the unit tests check every code is registered).
var sentences = map[Code]string{
	CodeRPCParse:    "The line is not one JSON-RPC 2.0 message within the size limit; send exactly one JSON object per line.",
	CodeRPCRequest:  "The message is not a valid JSON-RPC 2.0 request (jsonrpc \"2.0\", a string or integer id, a method, object params); fix the client.",
	CodeRPCMethod:   "This server answers initialize, ping, tools/list and tools/call only; call one of those.",
	CodeRPCParams:   "The params of this request are malformed; send the fields the MCP specification defines for this method.",
	CodeRPCInternal: "The request failed inside the agent; retry, and report it if it persists.",
	CodeUnknownTool: "No tool has that name; call tools/list and use one of the listed names.",
	CodeArgument:    "An argument is missing, unknown, of the wrong type or out of range; check the tool's input schema and call again.",

	CodeUsage:               "Usage: elyrn-agent mcp [--server URL] | init --server URL | whoami.",
	CodeServerURL:           "The server address must be https://host[:port], or http:// for localhost, 127.0.0.1, ::1 or a .onion host, with no path, query or credentials; fix --server.",
	CodeServerMissing:       "No identity exists yet, so the agent needs the server address; start it with --server URL.",
	CodeServerMismatch:      "This identity belongs to another server; start with that server's address, or move the identity file away to create a new identity.",
	CodeOnionProxy:          "A .onion server is reachable only through Tor; set ALL_PROXY to the Tor SOCKS address (for example socks5h://127.0.0.1:9050) and start again.",
	CodeProxy:               "The proxy configured in the environment (HTTPS_PROXY, HTTP_PROXY or ALL_PROXY) is malformed; fix or unset it and start again.",
	CodeConfigDir:           "The user configuration directory could not be determined; set HOME (or XDG_CONFIG_HOME on Linux, %AppData% on Windows) and start again.",
	CodeIdentityMissing:     "No identity exists yet; run elyrn-agent init --server URL, or call the identity tool.",
	CodeIdentityPermissions: "The identity file or its directory is open to other users; chmod 700 the directory and 600 the file, then start again.",
	CodeIdentityFile:        "The identity file could not be read or written, or is malformed; check the disk and the file, or move it away to create a new identity.",
	CodeIdentityUnknown:     "The server does not know this identity (never confirmed, deleted, or another database); move the identity file away and call identity to create a new one.",
	CodeIdentityMismatch:    "The server reports another public key for this identity; stop using this server and tell its operator.",

	CodeNetwork:          "The server could not be reached in time; check the address, the network or proxy, and retry.",
	CodeServerAnswer:     "The server sent an answer of the wrong shape or size; retry later, and tell the server's operator if it persists.",
	CodeServerBusy:       "The server is busy or failing; wait a minute and retry.",
	CodeRateLimited:      "The server is limiting requests from this agent; wait a minute before retrying.",
	CodeUnexpectedStatus: "The server refused the request with an unexpected status; retry, and tell the server's operator if it persists.",
	CodeProofOfWork:      "The proof of work was refused or demands more work than this agent allows; retry in a minute.",
	CodeBusy:             "Another call of this agent is still running; wait for it to finish and call again.",

	CodeRoomUnknown:   "This account is in no such room (it may have expired, been burned, or failed verification); call rooms to list the rooms you are in.",
	CodeRoomVerify:    "The server's data for this room does not match its code, so the room is hidden; do not trust this server with it.",
	CodeRoomCode:      "The room code is malformed; ask for the code again and pass it exactly as given (elyrn#...).",
	CodeRoomExpired:   "This room has expired; ask for a new room code.",
	CodeRoomNotFound:  "No room answers to this code (wrong, expired or burned); ask for a new room code.",
	CodeRoomFull:      "The room is full; ask its owner for a room with more seats.",
	CodeRoomLimit:     "max_members or ttl_hours exceeds this server's room limits; call again with smaller values.",
	CodeRoomCreate:    "The room could not be stored after several fresh codes; retry in a minute.",
	CodeRoster:        "The member list of this room failed verification; retry, and do not trust this server with the room if it persists.",
	CodeRosterChanged: "The room's members kept changing while the message was being sent; read the room, then send again.",
	CodeMessageText:   "The text is empty, longer than 2000 characters, contains control characters or does not fit one message; shorten or clean it and send again.",
	CodeSendUncertain: "The server did not confirm the message; read the room to see whether it arrived before sending it again.",
	CodeInternal:      "An internal error occurred in the agent; retry, and report it if it persists.",
}

// Sentence returns what the operator should do next for code.
func Sentence(code Code) string {
	if sentence, ok := sentences[code]; ok {
		return sentence
	}
	return sentences[CodeInternal]
}

// Registered reports whether code has a sentence.
func Registered(code Code) bool {
	_, ok := sentences[code]
	return ok
}

// Error is a failure with a registered code; cause is kept for the program, never shown.
type Error struct {
	Code  Code
	cause error
}

func (e *Error) Error() string { return string(e.Code) + ": " + Sentence(e.Code) }

func (e *Error) Unwrap() error { return e.cause }

// fail builds the error for code and logs the code (never the cause's text: it may hold a
// path, a room id or server words).
func fail(code Code, cause error) *Error {
	logger.Warn("failure code=%s", code)
	return &Error{Code: code, cause: cause}
}

// Fail is fail for the packages built on this one (the MCP layer, the command).
func Fail(code Code, cause error) *Error {
	return fail(code, cause)
}

// CodeOf returns the registered code of err, or CodeInternal for anything unregistered.
func CodeOf(err error) Code {
	var agentErr *Error
	if errors.As(err, &agentErr) && Registered(agentErr.Code) {
		return agentErr.Code
	}
	return CodeInternal
}
