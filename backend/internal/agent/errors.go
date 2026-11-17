package agent

// The one error home of elyrn-agent (the MCP layer and the command use it too). Every failure
// carries a registered code and a sentence that tells the operator what to do next; neither
// ever contains server text, system text, a path or a secret. The root cause stays reachable
// through errors.Is / errors.As for the program itself.

import (
	"errors"
	"strconv"

	"elyrn/internal/utils"
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
	CodeIdentityInUse       Code = "E_AGENT_IDENTITY_IN_USE"
	CodeIdentityUnconfirmed Code = "E_AGENT_IDENTITY_UNCONFIRMED"
	CodeStateFile           Code = "E_AGENT_STATE_FILE"
	CodeStateRebuilt        Code = "E_AGENT_STATE_REBUILT"
	CodeStateEvicted        Code = "E_AGENT_STATE_EVICTED"

	// Talking to the server
	CodeNetwork          Code = "E_AGENT_NETWORK"
	CodeTLS              Code = "E_AGENT_TLS"
	CodeServerAnswer     Code = "E_AGENT_SERVER_ANSWER"
	CodeServerBusy       Code = "E_AGENT_SERVER_BUSY"
	CodeServerRoute      Code = "E_AGENT_SERVER_ROUTE"
	CodeRateLimited      Code = "E_AGENT_RATE_LIMITED"
	CodeUnexpectedStatus Code = "E_AGENT_UNEXPECTED_STATUS"
	CodeProofOfWork      Code = "E_AGENT_POW"
	CodeBusy             Code = "E_AGENT_BUSY"
	CodeCallInFlight     Code = "E_AGENT_CALL_IN_FLIGHT"
	CodeStopped          Code = "E_AGENT_STOPPED"

	// Rooms
	CodeRoomUnknown     Code = "E_AGENT_ROOM_UNKNOWN"
	CodeRoomVerify      Code = "E_AGENT_ROOM_VERIFY"
	CodeRoomCode        Code = "E_AGENT_ROOM_CODE"
	CodeRoomCodeAltered Code = "E_AGENT_ROOM_CODE_ALTERED"
	CodeRoomExpired     Code = "E_AGENT_ROOM_EXPIRED"
	CodeRoomNotFound    Code = "E_AGENT_ROOM_NOT_FOUND"
	CodeRoomFull        Code = "E_AGENT_ROOM_FULL"
	CodeRoomLimit       Code = "E_AGENT_ROOM_LIMIT"
	CodeRoomCreate      Code = "E_AGENT_ROOM_CREATE"
	CodeRoster          Code = "E_AGENT_ROSTER"
	CodeRosterChanged   Code = "E_AGENT_ROSTER_CHANGED"
	CodeMessageText     Code = "E_AGENT_MESSAGE_TEXT"
	CodeSendUncertain   Code = "E_AGENT_SEND_UNCERTAIN"
	CodeMessageIDTaken  Code = "E_AGENT_MESSAGE_ID_TAKEN"
	CodeAccountNumber   Code = "E_AGENT_MESSAGE_IS_ACCOUNT_NUMBER"
	CodeReplay          Code = "E_AGENT_REPLAY"

	// Member roles
	CodeRoleText            Code = "E_AGENT_ROLE_TEXT"
	CodeRoleMemberUnknown   Code = "E_AGENT_ROLE_MEMBER_UNKNOWN"
	CodeRoleMemberAmbiguous Code = "E_AGENT_ROLE_MEMBER_AMBIGUOUS"
	CodeRoleNotAllowed      Code = "E_AGENT_ROLE_NOT_ALLOWED"
	CodeRoleMemberGone      Code = "E_AGENT_ROLE_MEMBER_GONE"
	CodeRoleIgnored         Code = "E_AGENT_ROLE_IGNORED" // log only: a served role shown as none

	CodeInternal Code = "E_AGENT_INTERNAL"
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
	CodeServerMismatch:      "This identity belongs to another server; start with that server's address, or restore the right identity file from a backup if this one replaced it. The file is the account's only copy: moving it away to create a new identity abandons the account and its rooms.",
	CodeOnionProxy:          "A .onion server is reachable only through Tor; set ALL_PROXY to the Tor SOCKS address (for example socks5h://127.0.0.1:9050) and start again.",
	CodeProxy:               "The proxy configured in the environment (HTTPS_PROXY, HTTP_PROXY or ALL_PROXY) is malformed; fix or unset it and start again.",
	CodeConfigDir:           "The user configuration directory could not be determined; set HOME (or XDG_CONFIG_HOME on Linux, %AppData% on Windows) and start again.",
	CodeIdentityMissing:     "No identity exists yet; run elyrn-agent init --server URL, or call the identity tool.",
	CodeIdentityPermissions: "The identity file or its directory is open to other users; chmod 700 the directory and 600 the file, then start again.",
	CodeIdentityFile:        "The identity file could not be read or written, or is malformed; check the disk and the file and restore it from a backup if you have one: it is the account's only copy, so moving it away abandons the account and creates a new identity.",
	CodeIdentityUnknown:     "The server does not know this identity (never confirmed, deleted, or another database); check --server and restore the identity file from a backup first if you have one. The file is the account's only copy: moving it away and calling identity creates a new account and abandons this one and its rooms.",
	CodeIdentityMismatch:    "The server reports another public key for this identity; stop using this server and tell its operator.",
	CodeIdentityInUse:       "Another elyrn-agent is using this identity; stop it, or give this one its own identity directory (another user or configuration directory).",
	CodeIdentityUnconfirmed: "This identity was never confirmed and the server no longer holds its registration, so it owns no account and nothing is lost by replacing it; move the identity file away and call identity to create a new one.",
	CodeStateFile:           "The message-counter file beside the identity could not be written or is malformed; check the disk and that file, then restore it from a backup or move it away (counters are then rebuilt from the visible messages).",
	CodeStateRebuilt:        "The message-counter file beside the identity was missing or unreadable, so counters are rebuilt from the visible messages; nothing to do unless this repeats.",
	CodeStateEvicted:        "The message-counter file reached its bound of " + strconv.Itoa(maxStateRooms) + " rooms, so the records of the rooms that expire soonest were dropped and replay detection there starts again from the visible messages; leave the rooms you no longer need.",

	CodeNetwork:          "The server could not be reached in time; check the address, the network or proxy, and retry.",
	CodeTLS:              "The secure connection to the server failed (certificate not trusted, expired, for another name, or the TLS handshake was refused); check the address, the system clock and any proxy that intercepts TLS, and tell the server's operator.",
	CodeServerAnswer:     "The server sent an answer of the wrong shape or size; retry later, and tell the server's operator if it persists.",
	CodeServerBusy:       "The server is temporarily unavailable (busy, restarting or failing); wait a minute and retry.",
	CodeServerRoute:      "The server's front end does not serve this request (unknown path or method, or a body over its bound), so the server and this agent may be of different releases; update the agent, and tell the server's operator if it persists.",
	CodeRateLimited:      "The server is limiting requests from this agent; wait a minute before retrying.",
	CodeUnexpectedStatus: "The server refused the request with an unexpected status; retry, and tell the server's operator if it persists.",
	CodeProofOfWork:      "The proof of work was refused or demands more work than this agent allows; retry in a minute.",
	CodeBusy:             "Another call of this agent is still running; wait for it to finish and call again.",
	CodeCallInFlight:     "Another tool call is still running (this agent runs one at a time); wait for its answer, or send notifications/cancelled for it, then call again.",
	CodeStopped:          "The agent is shutting down and takes no more calls; start it again.",

	CodeRoomUnknown:     "This account is in no such room (it may have expired, been burned, or failed verification); call rooms to list the rooms you are in.",
	CodeRoomVerify:      "The server's data for this room does not match its code, so the room is hidden; do not trust this server with it.",
	CodeRoomCode:        "The room code is malformed; ask for the code again and pass it exactly as given (elyrn#...).",
	CodeRoomCodeAltered: "This code names a room you are in, but with other limits than the code you joined with: it was altered. Ask for the code again.",
	CodeRoomExpired:     "This room has expired; ask for a new room code.",
	CodeRoomNotFound:    "No room answers to this code (wrong, expired or burned); ask for a new room code.",
	CodeRoomFull:        "The room is full; ask its owner for a room with more seats.",
	CodeRoomLimit:       "max_members or ttl_hours exceeds this server's room limits; call again with smaller values.",
	CodeRoomCreate:      "The room could not be stored after several fresh codes; retry in a minute.",
	CodeRoster:          "The member list of this room failed verification; retry, and do not trust this server with the room if it persists.",
	CodeRosterChanged:   "The room's members kept changing while the message was being sent; read the room, then send again.",
	CodeMessageText:     "The text is empty, longer than " + strconv.Itoa(MaxMessageChars) + " characters, contains control characters or does not fit one message; shorten or clean it and send again.",
	CodeSendUncertain:   "The server did not confirm the message; read the room to see whether it arrived before sending it again.",
	CodeMessageIDTaken:  "The server refused the message because its id was already in use, also under a fresh id, so it was not sent; send it again, and tell the server's operator if this repeats.",
	CodeAccountNumber:   "The text contains something that looks like an account number, which is the only key to an account; it was not sent. Remove it and send again.",
	CodeReplay:          "A message was served again under a new position, or out of order; it is listed in replays without its text. If this repeats, the server or a member is replaying old messages: do not trust this server with the room.",

	CodeRoleText:            "A role is 0 to " + strconv.Itoa(MaxRoleChars) + " letters, digits, - or _, without the # and not owner or you in any case or width; the empty role clears it. Fix the role and call again.",
	CodeRoleMemberUnknown:   "No verified member of this room has that code; call room_members and pass a member's code exactly as listed, or leave member out to set this agent's own role.",
	CodeRoleMemberAmbiguous: "Several verified members of this room share that code, so nothing was set; ask that member to set its own role.",
	CodeRoleNotAllowed:      "Only the room's owner may set another member's role; leave member out to set this agent's own role, or ask the owner.",
	CodeRoleMemberGone:      "The server no longer lists that member in this room (it left, or the room is gone); call room_members and try again.",
	CodeRoleIgnored:         "A member's role did not open under the room's code or broke the role rule, so that member is shown without a role; nothing to do unless it repeats.",
	CodeInternal:            "An internal error occurred in the agent; retry, and report it if it persists.",
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
// path, a room id or server words). fail and warn bound their lines per code (utils flood
// bound), so a burst of one code never silences another.
func fail(code Code, cause error) *Error {
	logger.At(utils.LogLevelWARN, string(code), "failure code=%s", code)
	return &Error{Code: code, cause: cause}
}

// warn logs a registered code the program recovers from by itself (never a cause's text).
func warn(code Code) {
	logger.At(utils.LogLevelWARN, string(code), "warning code=%s", code)
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
