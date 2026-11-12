// Package apperr is the single home of every failure the HTTP server answers: each Code names
// one cause, and the registry gives it a stable id, an HTTP status, the public sentence and
// the level it is logged at. Handlers and middleware never write a failure body themselves.
//
// The wire format is frozen: Write answers through http.Error, so status, body ("<sentence>\n")
// and headers are exactly what the call sites wrote before this package existed. Login's
// failures keep their JSON shape ({"success":false,"message":"<sentence>"}), written by the
// same encoder its success answer uses. Clients map
// these bodies (frontend/js/errors.js fromApi) and statuses (the agent), so a sentence or a
// status here changes only together with them.
package apperr

import (
	"net/http"

	"elyrn/internal/models"
	"elyrn/internal/utils"
)

// Code names one cause of a failed request. Several codes may share one public answer on
// purpose (see the registry); the code still tells the server-side log which cause it was.
type Code int

const (
	// Request shape
	MethodNotAllowed Code = iota + 1
	InvalidRequest
	RouteNotFound
	UnsupportedMediaType
	CrossOrigin

	// Sessions and registration
	NoSession
	SessionContextMissing
	MemberNotFound
	PendingTokenRequired
	PendingTokenInvalid
	AccountExists

	// Proof of work, rate limits and capacity
	PoWRequired
	PoWInvalid
	PoWRateLimited
	PoWCapacity
	RateLimited
	SubscriberLimit
	Argon2Busy
	PendingStoreFull
	StoreUnavailable

	// Chat service outcomes
	InvalidInput
	NotFound
	LimitReached
	Conflict
	RoomFull
	RosterChanged
	IdentityUnset
	Forbidden

	// Login: JSON-shaped answers (the browser maps the message, the agent the status)
	LoginBodyInvalid
	LoginKeyMalformed
	LoginLookupFailed
	LoginNoAccount
	LoginLegacyAccount

	// Server faults
	AccountCollision
	Internal
)

// Public sentences: each is written once here and shared by every code that answers with it.
const (
	sayMethodNotAllowed   = "Method not allowed"
	sayInvalidRequest     = "Invalid request"
	sayRouteNotFound      = "Not Found" // capital F: the mux 404, distinct from the chat 404 below
	sayNotFound           = "Not found"
	sayUnsupportedMedia   = "Unsupported Media Type"
	sayForbidden          = "Forbidden"
	sayUnauthorized       = "Unauthorized"
	sayPendingRequired    = "Pending token required"
	sayPoWRequired        = "Proof of work required"
	sayPoWInvalid         = "Invalid proof of work"
	sayTooManyRequests    = "Too many requests"
	sayUnavailable        = "Service unavailable"
	sayConflict           = "Conflict"
	sayRoomFull           = "Room full"
	sayRosterChanged      = "Roster changed"
	sayInternalServerErr  = "Internal server error"
	sayInvalidCredentials = "Invalid credentials"
)

// shape is how a failure is written on the wire.
type shape int

const (
	shapeText shape = iota // http.Error: "<sentence>\n", text/plain, nosniff
	shapeJSON              // {"success":false,"message":"<sentence>"}\n, application/json
)

// entry is what the registry knows about one code.
type entry struct {
	id     string         // stable E_... identifier, the only thing logs carry about the cause
	status int            // HTTP status on the wire
	body   string         // public sentence on the wire
	level  utils.LogLevel // level the failure is logged at
	shape  shape          // wire shape of the body
}

// registry holds every failure the server can answer. Deliberate merges (one public answer
// for several causes, so a client cannot tell them apart) are marked MERGE.
var registry = map[Code]entry{
	MethodNotAllowed: {"E_METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, sayMethodNotAllowed, utils.LogLevelWARN, shapeText},
	InvalidRequest:   {"E_INVALID_REQUEST", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeText},
	// MERGE: a malformed /conversations path answers like an unregistered path, so probing
	// the route shape learns nothing beyond "no such route"
	RouteNotFound:        {"E_ROUTE_NOT_FOUND", http.StatusNotFound, sayRouteNotFound, utils.LogLevelDEBUG, shapeText},
	UnsupportedMediaType: {"E_UNSUPPORTED_MEDIA_TYPE", http.StatusUnsupportedMediaType, sayUnsupportedMedia, utils.LogLevelWARN, shapeText},
	// MERGE: a foreign origin (CORS preflight or a cross-origin write) gets the same 403 as a
	// refused chat action; the reason stays in the server log
	CrossOrigin: {"E_CROSS_ORIGIN", http.StatusForbidden, sayForbidden, utils.LogLevelWARN, shapeText},

	// MERGE (all 401 "Unauthorized"): no session, a revoked or expired one, a session whose
	// account is gone, an invalid or expired pending token, and a confirmation for an account
	// that already exists. One answer, so neither sessions nor accounts can be enumerated
	NoSession:             {"E_NO_SESSION", http.StatusUnauthorized, sayUnauthorized, utils.LogLevelDEBUG, shapeText},
	SessionContextMissing: {"E_SESSION_CONTEXT_MISSING", http.StatusUnauthorized, sayUnauthorized, utils.LogLevelERROR, shapeText},
	MemberNotFound:        {"E_MEMBER_NOT_FOUND", http.StatusUnauthorized, sayUnauthorized, utils.LogLevelWARN, shapeText},
	PendingTokenRequired:  {"E_PENDING_TOKEN_REQUIRED", http.StatusBadRequest, sayPendingRequired, utils.LogLevelWARN, shapeText},
	PendingTokenInvalid:   {"E_PENDING_TOKEN_INVALID", http.StatusUnauthorized, sayUnauthorized, utils.LogLevelWARN, shapeText},
	AccountExists:         {"E_ACCOUNT_EXISTS", http.StatusUnauthorized, sayUnauthorized, utils.LogLevelWARN, shapeText},

	PoWRequired: {"E_POW_REQUIRED", http.StatusPreconditionFailed, sayPoWRequired, utils.LogLevelWARN, shapeText},
	PoWInvalid:  {"E_POW_INVALID", http.StatusForbidden, sayPoWInvalid, utils.LogLevelWARN, shapeText},
	// MERGE (all 429 "Too many requests"): every rate limit, the event-stream subscriber cap
	// and the chat service's own limits answer alike; which one tripped is not public
	PoWRateLimited:  {"E_POW_RATE_LIMITED", http.StatusTooManyRequests, sayTooManyRequests, utils.LogLevelWARN, shapeText},
	RateLimited:     {"E_RATE_LIMITED", http.StatusTooManyRequests, sayTooManyRequests, utils.LogLevelWARN, shapeText},
	SubscriberLimit: {"E_SUBSCRIBER_LIMIT", http.StatusTooManyRequests, sayTooManyRequests, utils.LogLevelWARN, shapeText},
	LimitReached:    {"E_LIMIT_REACHED", http.StatusTooManyRequests, sayTooManyRequests, utils.LogLevelWARN, shapeText},
	// MERGE (all 503 "Service unavailable"): a full PoW issuer, saturated Argon2id slots
	// (registration phase 2 only; login runs no Argon2id), a full pending-registration store
	// and an unreachable database
	PoWCapacity:      {"E_POW_CAPACITY", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	Argon2Busy:       {"E_ARGON2_BUSY", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	PendingStoreFull: {"E_PENDING_STORE_FULL", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	StoreUnavailable: {"E_STORE_UNAVAILABLE", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelERROR, shapeText},

	// InvalidInput is the service-side twin of InvalidRequest (same answer, separate log id)
	InvalidInput: {"E_INVALID_INPUT", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeText},
	// MERGE: the chat service answers ErrNotFound for an unknown, expired or burned
	// conversation or room, a wrong room code, and one the caller is not a member of
	NotFound:      {"E_NOT_FOUND", http.StatusNotFound, sayNotFound, utils.LogLevelDEBUG, shapeText},
	Conflict:      {"E_CONFLICT", http.StatusConflict, sayConflict, utils.LogLevelWARN, shapeText},
	RoomFull:      {"E_ROOM_FULL", http.StatusConflict, sayRoomFull, utils.LogLevelINFO, shapeText},
	RosterChanged: {"E_ROSTER_CHANGED", http.StatusPreconditionFailed, sayRosterChanged, utils.LogLevelINFO, shapeText},
	// MERGE: an account without an identity key and an action the caller may not take
	IdentityUnset: {"E_IDENTITY_UNSET", http.StatusForbidden, sayForbidden, utils.LogLevelWARN, shapeText},
	Forbidden:     {"E_FORBIDDEN", http.StatusForbidden, sayForbidden, utils.LogLevelWARN, shapeText},

	// Login answers in JSON (shapeJSON); a body that is not JSON is its InvalidRequest twin
	LoginBodyInvalid: {"E_LOGIN_BODY_INVALID", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeJSON},

	// MERGE (all 401 "Invalid credentials"): a malformed key, no account for the key, an
	// account without an identity key, and a lookup the server failed to compute (a server
	// fault kept at 401 by the clients' contract; its cause is logged). One answer, so an
	// account can be neither enumerated nor told apart from a damaged one
	LoginKeyMalformed:  {"E_LOGIN_KEY_MALFORMED", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},
	LoginLookupFailed:  {"E_LOGIN_LOOKUP_FAILED", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelERROR, shapeJSON},
	LoginNoAccount:     {"E_LOGIN_NO_ACCOUNT", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},
	LoginLegacyAccount: {"E_LOGIN_LEGACY_ACCOUNT", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},

	// MERGE: a phase-1 account-number collision is reported as a plain server fault
	AccountCollision: {"E_ACCOUNT_COLLISION", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
	Internal:         {"E_INTERNAL", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
}

var logger = utils.NewLogger("APPERR")

// lookup returns the registry entry; an unregistered code is a programming error and is
// answered as Internal rather than with an empty status.
func lookup(code Code) entry {
	if e, ok := registry[code]; ok {
		return e
	}
	logger.Error("unregistered error code %d", int(code))
	return registry[Internal]
}

// Write logs the failure once (operation name and code id, at the code's level; never
// request data) and answers with the registered status and sentence.
func Write(w http.ResponseWriter, op string, code Code) {
	e := lookup(code)
	logAt(e.level, op, e.id)
	send(w, e)
}

// WriteError answers err: a known sentinel gets its code; anything else is Internal, and only
// then is the cause logged (server side only, attributed to WriteError's caller).
func WriteError(w http.ResponseWriter, op string, err error) {
	if code, ok := CodeOf(err); ok {
		Write(w, op, code)
		return
	}
	e := registry[Internal]
	logger.LogErrorFrom(1, op+" ("+e.id+")", err)
	send(w, e)
}

// WriteCause answers code and logs err as its cause (server side only), for a server fault
// whose public answer a client contract fixes to something other than Internal.
func WriteCause(w http.ResponseWriter, op string, code Code, err error) {
	e := lookup(code)
	logger.LogErrorFrom(1, op+" ("+e.id+")", err)
	send(w, e)
}

// send is the only place a failure reaches the wire, in the code's registered shape.
func send(w http.ResponseWriter, e entry) {
	if e.shape == shapeJSON {
		sendJSON(w, e)
		return
	}
	sendText(w, e)
}

// sendText keeps the bytes the call sites always produced through http.Error: the sentence
// plus "\n", text/plain, nosniff.
func sendText(w http.ResponseWriter, e entry) {
	http.Error(w, e.body, e.status)
}

// sendJSON writes login's failure shape with the encoder and type its success answer uses,
// so the bytes are exactly those the handler wrote before.
func sendJSON(w http.ResponseWriter, e entry) {
	utils.EncodeJSONResponse(w, models.LoginResponse{Success: false, Message: e.body}, e.status)
}

// logAt is the one place a failure line is formatted.
func logAt(level utils.LogLevel, op, id string) {
	switch level {
	case utils.LogLevelDEBUG:
		logger.Debug("%s: %s", op, id)
	case utils.LogLevelINFO:
		logger.Info("%s: %s", op, id)
	case utils.LogLevelWARN:
		logger.Warn("%s: %s", op, id)
	default:
		logger.Error("%s: %s", op, id)
	}
}
