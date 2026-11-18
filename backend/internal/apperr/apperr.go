// Package apperr is the single home of every failure the HTTP server answers: each Code names
// one cause, and the registry gives it a stable id, an HTTP status, the public sentence and
// the level it is logged at. Handlers and middleware never write a failure body themselves.
//
// The wire format is frozen: Write answers through http.Error, so status, body ("<sentence>\n")
// and headers are exactly what the call sites wrote before this package existed. Login's
// failures keep their JSON shape ({"success":false,"message":"<sentence>"}), written by the
// same encoder its success answer uses; IDTaken uses that shape too, so clients can tell it
// from the other 409 of a send. Clients map
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
	HeadNotAllowed
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
	PendingStoreFull
	StoreUnavailable
	ShuttingDown
	RequestCancelled
	HealthUnavailable

	// Chat service outcomes
	InvalidInput
	NotFound
	LimitReached
	Conflict
	IDTaken
	RoomFull
	RosterChanged
	SenderCardMismatch
	IdentityUnset
	Forbidden
	RoleNotAllowed
	FilePartOutOfOrder
	FileQuotaReached
	FileShareReached
	FileStoreFull
	FileBudgetSpent
	FileRequestsBusy

	// Login: JSON-shaped answers (the browser maps the message, the agent the status)
	LoginBodyInvalid
	LoginKeyMalformed
	LoginLookupFailed
	LoginNoAccount
	LoginLegacyAccount

	// Server faults
	AccountCollision
	InputUnchecked
	Panic
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
	sayIDTaken            = "Id taken"
	sayRoomFull           = "Room full"
	sayRosterChanged      = "Roster changed"
	saySenderCardMismatch = "Sender card mismatch"
	sayRoleNotAllowed     = "Role not allowed"
	sayFilePartOutOfOrder = "File part out of order"
	sayFileQuotaReached   = "File quota reached"
	sayFileShareReached   = "File share reached"
	sayFileStoreFull      = "File store full"
	sayFileBudgetSpent    = "File budget spent"
	sayInternalServerErr  = "Internal server error"
	sayInvalidCredentials = "Invalid credentials"
)

// shape is how a failure is written on the wire.
type shape int

const (
	shapeText  shape = iota // http.Error: "<sentence>\n", text/plain, nosniff
	shapeJSON               // {"success":false,"message":"<sentence>"}\n, application/json
	shapeEmpty              // status line only: no body, no Content-Type (HEAD on the auth routes)
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
	// HEAD on register, login and the PoW challenge always answered a bare 405 (link previews
	// and health probes); the sentence is registered but never written (shapeEmpty)
	HeadNotAllowed: {"E_HEAD_NOT_ALLOWED", http.StatusMethodNotAllowed, sayMethodNotAllowed, utils.LogLevelDEBUG, shapeEmpty},
	InvalidRequest: {"E_INVALID_REQUEST", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeText},
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
	// MERGE (all 503 "Service unavailable"): a full PoW issuer or spent-challenge set, a full
	// pending-registration store and a database that is unreachable, restarting, out of
	// connections or too slow (store.ErrUnavailable, on every route; login included)
	PoWCapacity:      {"E_POW_CAPACITY", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	PendingStoreFull: {"E_PENDING_STORE_FULL", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	StoreUnavailable: {"E_STORE_UNAVAILABLE", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelERROR, shapeText},
	// MERGE: a request that reached the server while it closes its master keys (shutdown) is
	// refused like an outage, never sealed under a zeroized key (encryption.ErrClosing)
	ShuttingDown: {"E_SHUTTING_DOWN", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},
	// MERGE: work whose context was cancelled (context.Canceled: the client went away, or the
	// server's base context ended at shutdown) is neither an internal error nor worth an ERROR
	// line; the request paths detach their database work from cancellation
	// (middleware.DatabaseContext), so this is the backstop. Nobody may be there to read it; a
	// client that is gets "retry later"
	RequestCancelled: {"E_REQUEST_CANCELLED", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelINFO, shapeText},
	// The container healthcheck (loopback only): the database did not answer SELECT 1 in time,
	// or retention stopped cycling; a status line only, no detail
	HealthUnavailable: {"E_HEALTH_UNAVAILABLE", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeEmpty},

	// InvalidInput is the service-side twin of InvalidRequest (same answer, separate log id)
	InvalidInput: {"E_INVALID_INPUT", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeText},
	// MERGE: the chat service answers ErrNotFound for an unknown, expired or burned
	// conversation or room, a wrong room code, and one the caller is not a member of
	NotFound: {"E_NOT_FOUND", http.StatusNotFound, sayNotFound, utils.LogLevelDEBUG, shapeText},
	// Conflict on a send (a message or a note) means "your earlier attempt with this id is
	// stored" (or, for a note, "a note from you already waits for them"); IDTaken means the id
	// is held by anything else and nothing was stored: send again under a fresh id. IDTaken
	// answers in JSON so the browser, which reads only JSON bodies, can tell the two 409s apart
	// by message (frontend/js/errors.js API_MESSAGES), and the agent by the same field
	Conflict:      {"E_CONFLICT", http.StatusConflict, sayConflict, utils.LogLevelWARN, shapeText},
	IDTaken:       {"E_ID_TAKEN", http.StatusConflict, sayIDTaken, utils.LogLevelWARN, shapeJSON},
	RoomFull:      {"E_ROOM_FULL", http.StatusConflict, sayRoomFull, utils.LogLevelINFO, shapeText},
	RosterChanged: {"E_ROSTER_CHANGED", http.StatusPreconditionFailed, sayRosterChanged, utils.LogLevelINFO, shapeText},
	// SenderCardMismatch: a room message or note whose header card is not the sending member's
	// stored card. JSON for the reason IDTaken is: it shares 400 with the send's "Invalid
	// request", and a client must tell "use your stored card" from a malformed send
	SenderCardMismatch: {"E_SENDER_CARD_MISMATCH", http.StatusBadRequest, saySenderCardMismatch, utils.LogLevelWARN, shapeJSON},
	// MERGE: an account without an identity key and an action the caller may not take
	IdentityUnset: {"E_IDENTITY_UNSET", http.StatusForbidden, sayForbidden, utils.LogLevelWARN, shapeText},
	Forbidden:     {"E_FORBIDDEN", http.StatusForbidden, sayForbidden, utils.LogLevelWARN, shapeText},
	// The five below answer in JSON for the reason IDTaken does: each shares its status with
	// another answer of its route (a cross-origin 403, the send's two 409s, the other 507s), and
	// the browser tells them apart by message, the agent by the same field.
	// RoleNotAllowed: a member who does not own the room set another member's role
	RoleNotAllowed: {"E_ROLE_NOT_ALLOWED", http.StatusForbidden, sayRoleNotAllowed, utils.LogLevelWARN, shapeJSON},
	// FilePartOutOfOrder: a later part of a file whose part 0 the caller has not stored
	FilePartOutOfOrder: {"E_FILE_PART_OUT_OF_ORDER", http.StatusConflict, sayFilePartOutOfOrder, utils.LogLevelWARN, shapeJSON},
	// FileQuotaReached: the conversation holds FILE_CONVERSATION_QUOTA_BYTES of parts already
	FileQuotaReached: {"E_FILE_QUOTA_REACHED", http.StatusInsufficientStorage, sayFileQuotaReached, utils.LogLevelINFO, shapeJSON},
	// FileShareReached: the uploader holds its share of the conversation's quota already (the
	// quota over the conversation's seat bound, at least one largest file); others may still upload
	FileShareReached: {"E_FILE_SHARE_REACHED", http.StatusInsufficientStorage, sayFileShareReached, utils.LogLevelINFO, shapeJSON},
	// FileStoreFull: the server holds FILE_STORE_MAX_BYTES of parts, or does not know how many it
	// holds yet (fail closed); the operator's signal to raise the bound or wait for retention
	FileStoreFull: {"E_FILE_STORE_FULL", http.StatusInsufficientStorage, sayFileStoreFull, utils.LogLevelWARN, shapeJSON},
	// FileBudgetSpent: the account stored FILE_ACCOUNT_DAILY_BYTES of parts within the last day
	// (an in-memory budget); JSON, so it is told apart from the other 429s
	FileBudgetSpent: {"E_FILE_BUDGET_SPENT", http.StatusTooManyRequests, sayFileBudgetSpent, utils.LogLevelINFO, shapeJSON},
	// MERGE (503 "Service unavailable"): as many file part requests as memory allows are being
	// handled already (handlers.maxConcurrentFileRequests); retry later, like any outage
	FileRequestsBusy: {"E_FILE_REQUESTS_BUSY", http.StatusServiceUnavailable, sayUnavailable, utils.LogLevelWARN, shapeText},

	// Login answers in JSON (shapeJSON); a body that is not JSON is its InvalidRequest twin
	LoginBodyInvalid: {"E_LOGIN_BODY_INVALID", http.StatusBadRequest, sayInvalidRequest, utils.LogLevelWARN, shapeJSON},

	// MERGE (all 401 "Invalid credentials"): a malformed key, no account for the key and an
	// account without an identity key. One answer, so an account can be neither enumerated nor
	// told apart from a damaged one; 401 always means the key matches no usable account
	LoginKeyMalformed:  {"E_LOGIN_KEY_MALFORMED", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},
	LoginNoAccount:     {"E_LOGIN_NO_ACCOUNT", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},
	LoginLegacyAccount: {"E_LOGIN_LEGACY_ACCOUNT", http.StatusUnauthorized, sayInvalidCredentials, utils.LogLevelWARN, shapeJSON},
	// A lookup the server failed to compute (no or a short pepper, a crypto engine failure;
	// the cause is logged) is a server fault, never "invalid credentials" (which would tell the
	// user their only key is worthless). It is computed from the key alone, before any account
	// is read, so it fails alike for every key: the answer tells no account from another.
	LoginLookupFailed: {"E_LOGIN_LOOKUP_FAILED", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeJSON},

	// MERGE: a phase-1 account-number collision is reported as a plain server fault
	AccountCollision: {"E_ACCOUNT_COLLISION", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
	// MERGE: a handler reached without the input contract's gate (a wiring fault) is a plain
	// server fault; it never runs on input nobody checked
	InputUnchecked: {"E_INPUT_UNCHECKED", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
	// MERGE: a handler that panicked (recovered by middleware.Recover) is a plain server fault
	Panic:    {"E_PANIC", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
	Internal: {"E_INTERNAL", http.StatusInternalServerError, sayInternalServerErr, utils.LogLevelERROR, shapeText},
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

// Describe returns a code's stable id and HTTP status, for documents generated from tables
// that name codes (internal/contract).
func Describe(code Code) (id string, status int) {
	e := lookup(code)
	return e.id, e.status
}

// Write logs the failure once (operation name and code id, at the code's level; never
// request data; at most utils.LogBurst lines per code per utils.LogWindow, so a flood of free
// requests cannot fill the disk) and answers with the registered status and sentence.
func Write(w http.ResponseWriter, op string, code Code) {
	e := lookup(code)
	logAt(e.level, op, e.id)
	send(w, e)
}

// WriteError answers err: a known sentinel gets its code; anything else is Internal, and only
// then is the cause logged (server side only, attributed to WriteError's caller; a driver
// error reduced to its class by LogError's one reduction, database.LogSafe, so no statement
// value or address reaches it).
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
	switch e.shape {
	case shapeJSON:
		sendJSON(w, e)
	case shapeEmpty:
		w.WriteHeader(e.status)
	default:
		sendText(w, e)
	}
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

// logAt is the one place a failure line is formatted, at any level under the flood bound of its
// code id (utils.LogBurst lines per utils.LogWindow; LogError lines are bounded per operation).
func logAt(level utils.LogLevel, op, id string) {
	logger.At(level, id, "%s: %s", op, id)
}
