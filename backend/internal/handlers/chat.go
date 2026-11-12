package handlers

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/identity"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/internal/store"
	"elyrn/internal/utils"
)

const (
	conversationsPath = "/api/v2/conversations"
	// seq values are non-negative int64: at most 19 decimal digits
	maxSeqDigits = 19
)

// pageQueries whitelists the messages route's query parameters: each names a cursor kind and
// the lowest seq it accepts ("before=0" could only ever answer an empty page).
var pageQueries = map[string]struct {
	kind   chat.CursorKind
	minSeq int64
}{
	"after":  {chat.CursorAfter, 0},
	"before": {chat.CursorBefore, 1},
}

var chatService = chat.NewService()

// resolveMe turns the JWT-authenticated user into a chat member or writes the error.
func resolveMe(w http.ResponseWriter, r *http.Request) (*chat.Member, bool) {
	w.Header().Set("Cache-Control", "no-store")
	userUUID, ok := auth.GetUserUUID(r.Context())
	if !ok {
		apperr.Write(w, "resolveMe", apperr.SessionContextMissing)
		return nil, false
	}
	me, err := chatService.ResolveMember(userUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The session outlived its account: same answer as no session at all
			apperr.Write(w, "ResolveMember", apperr.MemberNotFound)
			return nil, false
		}
		apperr.WriteError(w, "ResolveMember", err)
		return nil, false
	}
	return me, true
}

// rejectQuery refuses a query string on endpoints that take none.
func rejectQuery(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		apperr.Write(w, "rejectQuery", apperr.InvalidRequest)
		return true
	}
	return false
}

func allowOrTooMany(w http.ResponseWriter, bucket string, me *chat.Member) bool {
	if middleware.AllowKey(bucket + ":" + me.StreamTag) {
		return true
	}
	apperr.Write(w, "allowOrTooMany:"+bucket, apperr.RateLimited)
	return false
}

// decodeOrReject decodes the JSON body into dst or answers 400; the decoder's message is not
// logged (it can quote request bytes).
func decodeOrReject(w http.ResponseWriter, r *http.Request, dst interface{}, op string) bool {
	if err := utils.DecodeJSONRequest(r, dst); err != nil {
		apperr.Write(w, op+": decode", apperr.InvalidRequest)
		return false
	}
	return true
}

// MeHandler: GET returns the caller's identity public key so the client can detect a server
// that swapped it (client compares against its own derivation); DELETE erases the account.
func MeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		apperr.Write(w, "MeHandler", apperr.MethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) {
		return
	}
	if r.Method == http.MethodDelete {
		deleteAccount(w, r, me)
		return
	}
	utils.EncodeJSONResponse(w, models.MeResponse{
		PublicKey:       me.PublicKey,
		MessageTTLDays:  config.GetMessageTTLDays(),
		RoomMaxMembers:  config.GetRoomMaxMembers(),
		RoomMaxTTLHours: config.GetRoomMaxTTLHours(),
	}, http.StatusOK)
}

// deleteAccount erases the caller once the request re-proves the account number (as its auth
// key): a live session alone, or a request riding on one, cannot erase an identity.
func deleteAccount(w http.ResponseWriter, r *http.Request, me *chat.Member) {
	if !allowOrTooMany(w, "delete", me) {
		return
	}
	var req models.DeleteAccountRequest
	if !decodeOrReject(w, r, &req, "deleteAccount") {
		return
	}
	if !identity.ValidateEncodedKey(req.AuthKey) {
		apperr.Write(w, "deleteAccount", apperr.InvalidRequest)
		return
	}
	streams, err := chatService.DeleteAccount(me, req.AuthKey)
	if err != nil {
		apperr.WriteError(w, "DeleteAccount", err)
		return
	}
	realtime.Default.Publish(streams, realtime.Event{Kind: realtime.KindConversation})
	realtime.Default.Kick(me.StreamTag) // this account's other devices
	auth.ClearAuthCookie(w)
	utils.EncodeJSONResponse(w, models.LoginResponse{Success: true, Message: "Account deleted"}, http.StatusOK)
}

// CreateInviteHandler issues a single-use pairing token (POST /api/v2/invites).
// Each invite costs a fresh proof of work, like each registration phase.
func CreateInviteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apperr.Write(w, "CreateInviteHandler", apperr.MethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "invite", me) {
		return
	}
	var req models.CreateInviteRequest
	if !decodeOrReject(w, r, &req, "CreateInviteHandler") {
		return
	}
	if !requireProofOfWork(w, req.PoW, "invite") {
		return
	}
	token, expiresAt, err := chatService.CreateInvite(me)
	if err != nil {
		apperr.WriteError(w, "CreateInvite", err)
		return
	}
	utils.EncodeJSONResponse(w, models.InviteResponse{Token: token, ExpiresAt: expiresAt.Unix()}, http.StatusCreated)
}

// RedeemInviteHandler pairs the caller with the invite creator (POST /api/v2/invites/redeem).
func RedeemInviteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apperr.Write(w, "RedeemInviteHandler", apperr.MethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "redeem", me) {
		return
	}
	var req models.RedeemInviteRequest
	if !decodeOrReject(w, r, &req, "RedeemInviteHandler") {
		return
	}
	conversation, creatorStream, err := chatService.RedeemInvite(me, req.Token)
	if err != nil {
		apperr.WriteError(w, "RedeemInvite", err)
		return
	}
	realtime.Default.Publish([]string{creatorStream}, realtime.Event{Kind: realtime.KindConversation})
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, http.StatusCreated)
}

// conversationRoute is a whitelisted /api/v2/conversations path: id, sub-resource, item id.
type conversationRoute struct {
	id   uuid.UUID
	sub  string
	item uuid.UUID
}

// parseConversationRoute whitelists: "", "/{id}", "/{id}/messages", "/{id}/read",
// "/{id}/members", "/{id}/notes", "/{id}/notes/{note id}".
func parseConversationRoute(path string) (conversationRoute, bool) {
	rest := strings.TrimPrefix(path, conversationsPath)
	if rest == "" {
		return conversationRoute{}, true
	}
	parts := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	if !strings.HasPrefix(rest, "/") || len(parts) > 3 {
		return conversationRoute{}, false
	}
	id, ok := utils.ParseCanonicalUUIDv4(parts[0])
	if !ok {
		return conversationRoute{}, false
	}
	if len(parts) == 1 {
		return conversationRoute{id: id}, true
	}
	switch {
	case len(parts) == 2 && (parts[1] == "messages" || parts[1] == "read" || parts[1] == "members" || parts[1] == "notes"):
		return conversationRoute{id: id, sub: parts[1]}, true
	case len(parts) == 3 && parts[1] == "notes":
		item, ok := utils.ParseCanonicalUUIDv4(parts[2])
		if !ok {
			return conversationRoute{}, false
		}
		return conversationRoute{id: id, sub: "notes", item: item}, true
	default:
		return conversationRoute{}, false
	}
}

// ConversationsHandler routes every /api/v2/conversations[/...] request.
func ConversationsHandler(w http.ResponseWriter, r *http.Request) {
	route, ok := parseConversationRoute(r.URL.Path)
	if !ok {
		apperr.Write(w, "ConversationsHandler", apperr.RouteNotFound)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok {
		return
	}

	id, sub := route.id, route.sub
	switch {
	case id == uuid.Nil && r.Method == http.MethodGet:
		listConversations(w, r, me)
	case id != uuid.Nil && sub == "" && r.Method == http.MethodDelete:
		burnConversation(w, r, me, id)
	case sub == "messages" && r.Method == http.MethodGet:
		listMessages(w, r, me, id)
	case sub == "messages" && r.Method == http.MethodPost:
		sendMessage(w, r, me, id)
	case sub == "read" && r.Method == http.MethodPost:
		markRead(w, r, me, id)
	case sub == "members" && r.Method == http.MethodGet:
		roomMembers(w, r, me, id)
	case sub == "notes" && route.item == uuid.Nil && r.Method == http.MethodGet:
		listNotes(w, r, me, id)
	case sub == "notes" && route.item == uuid.Nil && r.Method == http.MethodPost:
		sendNote(w, r, me, id)
	case sub == "notes" && route.item != uuid.Nil && r.Method == http.MethodDelete:
		deleteNote(w, r, me, id, route.item)
	default:
		apperr.Write(w, "ConversationsHandler", apperr.MethodNotAllowed)
	}
}

func listConversations(w http.ResponseWriter, r *http.Request, me *chat.Member) {
	if rejectQuery(w, r) {
		return
	}
	conversations, err := chatService.ListConversations(me)
	if err != nil {
		apperr.WriteError(w, "ListConversations", err)
		return
	}
	utils.EncodeJSONResponse(w, models.ConversationsResponse{Conversations: conversations}, http.StatusOK)
}

func burnConversation(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	peers, err := chatService.BurnConversation(me, id)
	if err != nil {
		apperr.WriteError(w, "BurnConversation", err)
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusNoContent)
}

// parsePageCursor accepts no query at all (the latest page) or exactly one whitelisted
// "<name>=<decimal int64>" at or above that name's lowest seq; anything else is refused.
func parsePageCursor(r *http.Request) (chat.PageCursor, bool) {
	if r.URL.RawQuery == "" {
		return chat.PageCursor{Kind: chat.CursorLatest}, true
	}
	values := r.URL.Query()
	if len(values) != 1 {
		return chat.PageCursor{}, false
	}
	for name, raw := range values {
		query, known := pageQueries[name]
		if !known || len(raw) != 1 {
			return chat.PageCursor{}, false
		}
		seq, ok := parseSeq(raw[0])
		if !ok || seq < query.minSeq {
			return chat.PageCursor{}, false
		}
		return chat.PageCursor{Kind: query.kind, Seq: seq}, true
	}
	return chat.PageCursor{}, false
}

// parseSeq accepts 1..maxSeqDigits ASCII digits that fit an int64 (no sign, no exponent).
func parseSeq(raw string) (int64, bool) {
	if len(raw) == 0 || len(raw) > maxSeqDigits {
		return 0, false
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, false
		}
	}
	seq, err := strconv.ParseInt(raw, 10, 64)
	return seq, err == nil
}

func listMessages(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	cursor, ok := parsePageCursor(r)
	if !ok {
		apperr.Write(w, "listMessages", apperr.InvalidRequest)
		return
	}
	messages, err := chatService.ListMessages(me, id, cursor)
	if err != nil {
		apperr.WriteError(w, "ListMessages", err)
		return
	}
	utils.EncodeJSONResponse(w, models.MessagesResponse{Messages: messages}, http.StatusOK)
}

func sendMessage(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) || !allowOrTooMany(w, "msg", me) {
		return
	}
	var req models.SendMessageRequest
	if !decodeOrReject(w, r, &req, "sendMessage") {
		return
	}
	seq, peers, err := chatService.SendMessage(me, id, req.ID, req.Ciphertext)
	if err != nil {
		apperr.WriteError(w, "SendMessage", err)
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindMessage, ConversationID: id.String()})
	utils.EncodeJSONResponse(w, models.SendMessageResponse{Seq: seq}, http.StatusCreated)
}

func markRead(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	var req models.MarkReadRequest
	if !decodeOrReject(w, r, &req, "markRead") {
		return
	}
	if err := chatService.MarkRead(me, id, req.Seq); err != nil {
		apperr.WriteError(w, "MarkRead", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- rooms ----------

// CreateRoomHandler stores a room the client derived from a fresh room code (POST /api/v2/rooms).
// Each room costs a proof of work, like each invite.
func CreateRoomHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apperr.Write(w, "CreateRoomHandler", apperr.MethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "room", me) {
		return
	}
	var req models.CreateRoomRequest
	if !decodeOrReject(w, r, &req, "CreateRoomHandler") {
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault)
	if err != nil {
		apperr.WriteError(w, "CreateRoom", err)
		return
	}
	in.MaxMembers = req.MaxMembers
	in.ExpiresAt = time.Unix(req.ExpiresAt, 0)
	if !requireProofOfWork(w, req.PoW, "room") {
		return
	}
	conversation, err := chatService.CreateRoom(me, in)
	if err != nil {
		apperr.WriteError(w, "CreateRoom", err)
		return
	}
	realtime.Default.Publish([]string{me.StreamTag}, realtime.Event{Kind: realtime.KindConversation})
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, http.StatusCreated)
}

// JoinRoomHandler takes a seat in a room whose code the caller holds (POST /api/v2/rooms/join):
// 201 for a new seat, 200 when the caller was already a member.
func JoinRoomHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apperr.Write(w, "JoinRoomHandler", apperr.MethodNotAllowed)
		return
	}
	me, ok := resolveMe(w, r)
	if !ok || rejectQuery(w, r) || !allowOrTooMany(w, "join", me) {
		return
	}
	var req models.JoinRoomRequest
	if !decodeOrReject(w, r, &req, "JoinRoomHandler") {
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault)
	if err != nil {
		apperr.WriteError(w, "JoinRoom", err)
		return
	}
	conversation, created, peers, err := chatService.JoinRoom(me, in)
	if err != nil {
		apperr.WriteError(w, "JoinRoom", err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		realtime.Default.Publish(append(peers, me.StreamTag), realtime.Event{Kind: realtime.KindConversation})
	}
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, status)
}

func roomMembers(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	members, err := chatService.RoomMembers(me, id)
	if err != nil {
		apperr.WriteError(w, "RoomMembers", err)
		return
	}
	utils.EncodeJSONResponse(w, models.RoomMembersResponse{Members: members}, http.StatusOK)
}

func listNotes(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	notes, err := chatService.ListNotes(me, id)
	if err != nil {
		apperr.WriteError(w, "ListNotes", err)
		return
	}
	utils.EncodeJSONResponse(w, models.NotesResponse{Notes: notes}, http.StatusOK)
}

func sendNote(w http.ResponseWriter, r *http.Request, me *chat.Member, id uuid.UUID) {
	if rejectQuery(w, r) || !allowOrTooMany(w, "note", me) {
		return
	}
	var req models.SendNoteRequest
	if !decodeOrReject(w, r, &req, "sendNote") {
		return
	}
	recipient, err := chatService.SendNote(me, id, req.ID, req.To, req.Blob)
	if err != nil {
		apperr.WriteError(w, "SendNote", err)
		return
	}
	realtime.Default.Publish([]string{recipient}, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusCreated)
}

func deleteNote(w http.ResponseWriter, r *http.Request, me *chat.Member, id, noteID uuid.UUID) {
	if rejectQuery(w, r) {
		return
	}
	if err := chatService.DeleteNote(me, id, noteID); err != nil {
		apperr.WriteError(w, "DeleteNote", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
