// Package contract is the server's input contract: one table that states, for every endpoint,
// the methods, query parameters, content type, body bound and JSON fields it accepts, each
// field with its whitelist, and one gate (Gate) that refuses everything else before a handler
// runs. It is its own package, not part of utils, because the table names the answers
// (apperr) and the routes (models), and utils sits below both; handlers read what the gate
// admitted and keep only the checks that need state (sessions, membership, clocks, limits).
//
// docs/api/input-contract.md is rendered from this table (go generate, see render.go).
package contract

//go:generate go run gen_doc.go

import (
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/models"
)

// Kind is a JSON field's type.
type Kind int

const (
	KindString Kind = iota + 1
	KindInt
	KindBool
	KindObject
)

// Field is one JSON body field. A null value counts as absent (encoding/json leaves the Go
// field untouched), so it meets Required like a missing key does.
type Field struct {
	Name     string
	Kind     Kind
	Required bool
	Str      *Pattern  // KindString
	Int      *IntRange // KindInt
	Fields   []Field   // KindObject
	Missing  apperr.Code
	Invalid  apperr.Code
}

// Body is what an operation accepts as its request body (always one JSON object).
type Body struct {
	Fields []Field
	// Optional: an empty body stands for {} (registration phase 1 has always allowed it)
	Optional bool
	// Refuse answers a body that is not exactly the declared JSON shape: too large, not JSON,
	// a duplicate or unknown key, a wrong type, nesting, or a second value
	Refuse apperr.Code
}

// QueryParam is one accepted query parameter: raw text (never percent-decoded) checked by a
// pattern, then its integer value by a range.
type QueryParam struct {
	Name string
	Text *Pattern
	Int  *IntRange
}

// OpID names one operation (path + method); handlers dispatch on it.
type OpID int

const (
	OpPoWChallenge OpID = iota + 1
	OpRegister
	OpLogin
	OpLogout
	OpMeGet
	OpMeDelete
	OpInviteCreate
	OpInviteRedeem
	OpRoomCreate
	OpRoomJoin
	OpConversationList
	OpConversationBurn
	OpMessageList
	OpMessageSend
	OpReadMark
	OpMemberList
	OpNoteList
	OpNoteSend
	OpNoteDelete
	OpEvents
)

// Op is one accepted method on one endpoint.
type Op struct {
	ID     OpID
	Method string
	Query  []QueryParam
	// MaxQuery is how many of Query one request may carry (the page cursors are exclusive)
	MaxQuery int
	Body     *Body // nil: the operation takes no body
}

// Endpoint is one path template with its operations. Path parameters ("{id}", "{note}") are
// canonical UUIDv4s, handed to the handler parsed, in order (PathConversation, PathNote).
type Endpoint struct {
	Template string
	// BareHead: HEAD answers a bare 405 (apperr.HeadNotAllowed), as these routes always did
	BareHead bool
	Ops      []Op
	segments []segment
}

// Path parameter positions, in template order
const (
	PathConversation = iota
	PathNote
	maxPathParams
)

// Template parameter names; every one is a canonical UUIDv4
const (
	paramConversation = "{id}"
	paramNote         = "{note}"
)

// Fields shared by several bodies
var (
	powFields = []Field{
		{Name: "challenge", Kind: KindString, Required: true, Str: patternChallenge, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
		{Name: "solution", Kind: KindString, Required: true, Str: patternSolution, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
		{Name: "timestamp", Kind: KindInt, Required: true, Int: rangeUnixTime, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
		{Name: "ttl", Kind: KindInt, Required: true, Int: rangeTTL, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
		{Name: "difficulty", Kind: KindInt, Required: true, Int: rangeDifficulty, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
		{Name: "salt", Kind: KindString, Required: true, Str: patternSalt, Missing: apperr.PoWInvalid, Invalid: apperr.PoWInvalid},
	}
	// powField: missing answers 412 and a malformed solution 403, as pow.ValidateSolution did
	powField    = Field{Name: "pow", Kind: KindObject, Required: true, Fields: powFields, Missing: apperr.PoWRequired}
	idField     = Field{Name: "id", Kind: KindString, Required: true, Str: patternUUIDv4}
	lookupField = Field{Name: "lookup", Kind: KindString, Required: true, Str: patternKey32}
	cardField   = Field{Name: "card", Kind: KindString, Required: true, Str: patternRoomCard}
	vaultField  = Field{Name: "vault", Kind: KindString, Required: true, Str: patternRoomVault}

	// pageQueries: at most one cursor; "before=0" could only ever answer an empty page
	pageQueries = []QueryParam{
		{Name: models.QueryAfter, Text: patternSeqQuery, Int: rangeAfter},
		{Name: models.QueryBefore, Text: patternSeqQuery, Int: rangeSeq},
	}
)

// jsonBody is a required body answered 400 "Invalid request" when malformed.
func jsonBody(fields ...Field) *Body {
	return &Body{Fields: fields, Refuse: apperr.InvalidRequest}
}

// authEndpoints: the unauthenticated routes. The field order is the check order: it keeps
// the answer each multi-fault body got before (proof of work before the pending token).
func authEndpoints() []Endpoint {
	return []Endpoint{
		{Template: models.PathPoWChallenge, BareHead: true, Ops: []Op{{ID: OpPoWChallenge, Method: http.MethodGet}}},
		{Template: models.PathRegister, BareHead: true, Ops: []Op{{ID: OpRegister, Method: http.MethodPost, Body: &Body{
			Fields: []Field{
				powField,
				{Name: "confirm", Kind: KindBool},
				{Name: "pending_token", Kind: KindString, Str: patternPendingToken, Invalid: apperr.PendingTokenInvalid},
			},
			// A body that was not JSON used to be read as an empty phase 1 request, which has
			// no proof of work: 412 is what every such body got
			Optional: true, Refuse: apperr.PoWRequired,
		}}}},
		{Template: models.PathLogin, BareHead: true, Ops: []Op{{ID: OpLogin, Method: http.MethodPost, Body: &Body{
			Fields: []Field{{Name: "auth_key", Kind: KindString, Required: true, Str: patternKey32,
				Missing: apperr.LoginKeyMalformed, Invalid: apperr.LoginKeyMalformed}},
			Refuse: apperr.LoginBodyInvalid,
		}}}},
		{Template: models.PathLogout, Ops: []Op{{ID: OpLogout, Method: http.MethodPost}}},
		{Template: models.PathMe, Ops: []Op{
			{ID: OpMeGet, Method: http.MethodGet},
			{ID: OpMeDelete, Method: http.MethodDelete, Body: jsonBody(Field{Name: "auth_key", Kind: KindString, Required: true, Str: patternKey32})},
		}},
		{Template: models.PathEvents, Ops: []Op{{ID: OpEvents, Method: http.MethodGet}}},
	}
}

// chatEndpoints: invites, rooms and conversations (all behind a session).
func chatEndpoints() []Endpoint {
	conversation := models.PathConversations + "/" + paramConversation
	return []Endpoint{
		{Template: models.PathInvites, Ops: []Op{{ID: OpInviteCreate, Method: http.MethodPost, Body: jsonBody(powField)}}},
		{Template: models.PathInvitesRedeem, Ops: []Op{{ID: OpInviteRedeem, Method: http.MethodPost,
			Body: jsonBody(Field{Name: "token", Kind: KindString, Required: true, Str: patternInviteToken})}}},
		// Room fields first, then the proof of work, then the creator's limits: the order the
		// handler checked them in
		{Template: models.PathRooms, Ops: []Op{{ID: OpRoomCreate, Method: http.MethodPost, Body: jsonBody(
			idField, lookupField, cardField, vaultField, powField,
			Field{Name: "max_members", Kind: KindInt, Required: true, Int: rangeMaxMembers},
			Field{Name: "expires_at", Kind: KindInt, Required: true, Int: rangeExpiry},
		)}}},
		{Template: models.PathRoomsJoin, Ops: []Op{{ID: OpRoomJoin, Method: http.MethodPost, Body: jsonBody(idField, lookupField, cardField, vaultField)}}},
		{Template: models.PathConversations, Ops: []Op{{ID: OpConversationList, Method: http.MethodGet}}},
		{Template: conversation, Ops: []Op{{ID: OpConversationBurn, Method: http.MethodDelete}}},
		{Template: conversation + "/" + models.SubMessages, Ops: []Op{
			{ID: OpMessageList, Method: http.MethodGet, Query: pageQueries, MaxQuery: 1},
			{ID: OpMessageSend, Method: http.MethodPost, Body: jsonBody(idField,
				Field{Name: "ciphertext", Kind: KindString, Required: true, Str: patternMessage})},
		}},
		{Template: conversation + "/" + models.SubRead, Ops: []Op{{ID: OpReadMark, Method: http.MethodPost,
			Body: jsonBody(Field{Name: "seq", Kind: KindInt, Required: true, Int: rangeSeq})}}},
		{Template: conversation + "/" + models.SubMembers, Ops: []Op{{ID: OpMemberList, Method: http.MethodGet}}},
		{Template: conversation + "/" + models.SubNotes, Ops: []Op{
			{ID: OpNoteList, Method: http.MethodGet},
			{ID: OpNoteSend, Method: http.MethodPost, Body: jsonBody(idField,
				Field{Name: "to", Kind: KindString, Required: true, Str: patternRoomCard},
				Field{Name: "blob", Kind: KindString, Required: true, Str: patternNote})},
		}},
		{Template: conversation + "/" + models.SubNotes + "/" + paramNote, Ops: []Op{{ID: OpNoteDelete, Method: http.MethodDelete}}},
	}
}

// endpoints is the whole table, built once at init (templates split into segments).
var endpoints = buildTable(append(authEndpoints(), chatEndpoints()...))

// Endpoints returns the table, for the generated document and the tests.
func Endpoints() []Endpoint { return endpoints }
