package handlers

import (
	"errors"
	"net/http"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/config"
	"elyrn/internal/contract"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/internal/store"
	"elyrn/internal/utils"
)

const (
	// Rate-limit buckets per action: each namespaces a key "<bucket>:<stream tag>", and the
	// two PoW-gated ones double as the proof-of-work action
	bucketDelete = "delete"
	bucketInvite = "invite"
	bucketRedeem = "redeem"
	bucketMsg    = "msg"
	bucketRoom   = "room"
	bucketJoin   = "join"
	bucketNote   = "note"
)

// pageCursors maps each page query the contract admits to its cursor kind
var pageCursors = map[string]chat.CursorKind{
	models.QueryAfter:  chat.CursorAfter,
	models.QueryBefore: chat.CursorBefore,
}

var chatService = chat.NewService()

// resolveMe turns the JWT-authenticated user into a chat member or writes the error. It also
// returns the chat service bound to the request (its one database deadline, set by
// middleware.RequestDeadline), which serves the rest of the request.
func resolveMe(w http.ResponseWriter, r *http.Request) (*chat.Service, *chat.Member, bool) {
	w.Header().Set(utils.HeaderCacheControl, utils.CacheNoStore)
	userUUID, ok := auth.GetUserUUID(r.Context())
	if !ok {
		apperr.Write(w, "resolveMe", apperr.SessionContextMissing)
		return nil, nil, false
	}
	svc := chatService.WithContext(r.Context())
	me, err := svc.ResolveMember(userUUID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// The session outlived its account: same answer as no session at all
			apperr.Write(w, "ResolveMember", apperr.MemberNotFound)
			return nil, nil, false
		}
		apperr.WriteError(w, "ResolveMember", err)
		return nil, nil, false
	}
	return svc, me, true
}

func allowOrTooMany(w http.ResponseWriter, bucket string, me *chat.Member) bool {
	if middleware.AllowKey(bucket + ":" + me.StreamTag) {
		return true
	}
	apperr.Write(w, "allowOrTooMany:"+bucket, apperr.RateLimited)
	return false
}

// admitted returns what the input contract's gate admitted for r, or answers 500 when the
// route was wired without the gate (never run a handler on unchecked input).
func admitted(w http.ResponseWriter, r *http.Request, op string) (*contract.Input, bool) {
	in, ok := contract.InputOf(r)
	if !ok {
		apperr.Write(w, op, apperr.InputUnchecked)
		return nil, false
	}
	return in, true
}

// bindInput fills dst from the body the gate admitted (every field already whitelisted).
func bindInput(w http.ResponseWriter, r *http.Request, dst any, op string) bool {
	in, ok := admitted(w, r, op)
	if !ok {
		return false
	}
	if err := in.Bind(dst); err != nil {
		apperr.WriteError(w, op+": Bind", err)
		return false
	}
	return true
}

// MeHandler: GET returns the caller's identity public key so the client can detect a server
// that swapped it (client compares against its own derivation); DELETE erases the account.
func MeHandler(w http.ResponseWriter, r *http.Request) {
	in, ok := admitted(w, r, "MeHandler")
	if !ok {
		return
	}
	svc, me, ok := resolveMe(w, r)
	if !ok {
		return
	}
	if in.Op.ID == contract.OpMeDelete {
		deleteAccount(w, r, svc, me)
		return
	}
	utils.EncodeJSONResponse(w, models.MeResponse{
		PublicKey:        me.PublicKey,
		MessageTTLDays:   config.GetMessageTTLDays(),
		RoomMaxMembers:   config.GetRoomMaxMembers(),
		RoomMaxTTLHours:  config.GetRoomMaxTTLHours(),
		MessagePageLimit: config.GetMessagePageLimit(),
	}, http.StatusOK)
}

// deleteAccount erases the caller once the request re-proves the account number (as its auth
// key): a live session alone, or a request riding on one, cannot erase an identity.
func deleteAccount(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member) {
	if !allowOrTooMany(w, bucketDelete, me) {
		return
	}
	var req models.DeleteAccountRequest // auth_key: canonical base64url of 32 bytes (contract)
	if !bindInput(w, r, &req, "deleteAccount") {
		return
	}
	streams, err := svc.DeleteAccount(me, req.AuthKey)
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
	svc, me, ok := resolveMe(w, r)
	if !ok || !allowOrTooMany(w, bucketInvite, me) {
		return
	}
	var req models.CreateInviteRequest
	if !bindInput(w, r, &req, "CreateInviteHandler") {
		return
	}
	if !requireProofOfWork(w, req.PoW, bucketInvite) {
		return
	}
	token, expiresAt, err := svc.CreateInvite(me)
	if err != nil {
		apperr.WriteError(w, "CreateInvite", err)
		return
	}
	utils.EncodeJSONResponse(w, models.InviteResponse{Token: token, ExpiresAt: expiresAt.Unix()}, http.StatusCreated)
}

// RedeemInviteHandler pairs the caller with the invite creator (POST /api/v2/invites/redeem).
func RedeemInviteHandler(w http.ResponseWriter, r *http.Request) {
	svc, me, ok := resolveMe(w, r)
	if !ok || !allowOrTooMany(w, bucketRedeem, me) {
		return
	}
	var req models.RedeemInviteRequest
	if !bindInput(w, r, &req, "RedeemInviteHandler") {
		return
	}
	conversation, creatorStream, err := svc.RedeemInvite(me, req.Token)
	if err != nil {
		apperr.WriteError(w, "RedeemInvite", err)
		return
	}
	realtime.Default.Publish([]string{creatorStream}, realtime.Event{Kind: realtime.KindConversation})
	utils.EncodeJSONResponse(w, models.ConversationResponse{Conversation: *conversation}, http.StatusCreated)
}

// ConversationsHandler routes every /api/v2/conversations[/...] request by the operation the
// gate matched (path template and method), with the ids it parsed from the path.
func ConversationsHandler(w http.ResponseWriter, r *http.Request) {
	in, ok := admitted(w, r, "ConversationsHandler")
	if !ok {
		return
	}
	svc, me, ok := resolveMe(w, r)
	if !ok {
		return
	}
	id := in.PathID(contract.PathConversation)
	switch in.Op.ID {
	case contract.OpConversationList:
		listConversations(w, svc, me)
	case contract.OpConversationBurn:
		burnConversation(w, svc, me, id)
	case contract.OpMessageList:
		listMessages(w, in, svc, me, id)
	case contract.OpMessageSend:
		sendMessage(w, r, svc, me, id)
	case contract.OpReadMark:
		markRead(w, r, svc, me, id)
	case contract.OpMemberList:
		roomMembers(w, svc, me, id)
	case contract.OpNoteList:
		listNotes(w, svc, me, id)
	case contract.OpNoteSend:
		sendNote(w, r, svc, me, id)
	case contract.OpNoteDelete:
		deleteNote(w, svc, me, id, in.PathID(contract.PathNote))
	default:
		// The table routed another endpoint's operation here: a wiring fault
		apperr.Write(w, "ConversationsHandler", apperr.InputUnchecked)
	}
}

func listConversations(w http.ResponseWriter, svc *chat.Service, me *chat.Member) {
	conversations, err := svc.ListConversations(me)
	if err != nil {
		apperr.WriteError(w, "ListConversations", err)
		return
	}
	utils.EncodeJSONResponse(w, models.ConversationsResponse{Conversations: conversations}, http.StatusOK)
}

func burnConversation(w http.ResponseWriter, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	peers, err := svc.BurnConversation(me, id)
	if err != nil {
		apperr.WriteError(w, "BurnConversation", err)
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusNoContent)
}

// pageCursor turns the admitted query (none, or exactly one whitelisted cursor) into a cursor.
func pageCursor(in *contract.Input) chat.PageCursor {
	for name, kind := range pageCursors {
		if seq, ok := in.Query(name); ok {
			return chat.PageCursor{Kind: kind, Seq: seq}
		}
	}
	return chat.PageCursor{Kind: chat.CursorLatest}
}

func listMessages(w http.ResponseWriter, in *contract.Input, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	messages, err := svc.ListMessages(me, id, pageCursor(in))
	if err != nil {
		apperr.WriteError(w, "ListMessages", err)
		return
	}
	utils.EncodeJSONResponse(w, models.MessagesResponse{Messages: messages}, http.StatusOK)
}

func sendMessage(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	if !allowOrTooMany(w, bucketMsg, me) {
		return
	}
	var req models.SendMessageRequest
	if !bindInput(w, r, &req, "sendMessage") {
		return
	}
	seq, peers, err := svc.SendMessage(me, id, req.ID, req.Ciphertext)
	if err != nil {
		apperr.WriteError(w, "SendMessage", err)
		return
	}
	realtime.Default.Publish(peers, realtime.Event{Kind: realtime.KindMessage, ConversationID: id.String()})
	utils.EncodeJSONResponse(w, models.SendMessageResponse{Seq: seq}, http.StatusCreated)
}

func markRead(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	var req models.MarkReadRequest
	if !bindInput(w, r, &req, "markRead") {
		return
	}
	if err := svc.MarkRead(me, id, req.Seq); err != nil {
		apperr.WriteError(w, "MarkRead", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- rooms ----------

// CreateRoomHandler stores a room the client derived from a fresh room code (POST /api/v2/rooms).
// Each room costs a proof of work, like each invite.
func CreateRoomHandler(w http.ResponseWriter, r *http.Request) {
	svc, me, ok := resolveMe(w, r)
	if !ok || !allowOrTooMany(w, bucketRoom, me) {
		return
	}
	var req models.CreateRoomRequest
	if !bindInput(w, r, &req, "CreateRoomHandler") {
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault, req.MaxMembers, req.ExpiresAt)
	if err != nil {
		apperr.WriteError(w, "CreateRoom", err)
		return
	}
	if !requireProofOfWork(w, req.PoW, bucketRoom) {
		return
	}
	conversation, err := svc.CreateRoom(me, in)
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
	svc, me, ok := resolveMe(w, r)
	if !ok || !allowOrTooMany(w, bucketJoin, me) {
		return
	}
	var req models.JoinRoomRequest
	if !bindInput(w, r, &req, "JoinRoomHandler") {
		return
	}
	in, err := chat.ParseRoomInput(req.ID, req.Lookup, req.Card, req.Vault, req.MaxMembers, req.ExpiresAt)
	if err != nil {
		apperr.WriteError(w, "JoinRoom", err)
		return
	}
	conversation, created, peers, err := svc.JoinRoom(me, in)
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

func roomMembers(w http.ResponseWriter, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	members, err := svc.RoomMembers(me, id)
	if err != nil {
		apperr.WriteError(w, "RoomMembers", err)
		return
	}
	utils.EncodeJSONResponse(w, models.RoomMembersResponse{Members: members}, http.StatusOK)
}

func listNotes(w http.ResponseWriter, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	notes, err := svc.ListNotes(me, id)
	if err != nil {
		apperr.WriteError(w, "ListNotes", err)
		return
	}
	utils.EncodeJSONResponse(w, models.NotesResponse{Notes: notes}, http.StatusOK)
}

func sendNote(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	if !allowOrTooMany(w, bucketNote, me) {
		return
	}
	var req models.SendNoteRequest
	if !bindInput(w, r, &req, "sendNote") {
		return
	}
	recipient, err := svc.SendNote(me, id, req.ID, req.To, req.Blob)
	if err != nil {
		apperr.WriteError(w, "SendNote", err)
		return
	}
	realtime.Default.Publish([]string{recipient}, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusCreated)
}

func deleteNote(w http.ResponseWriter, svc *chat.Service, me *chat.Member, id, noteID uuid.UUID) {
	if err := svc.DeleteNote(me, id, noteID); err != nil {
		apperr.WriteError(w, "DeleteNote", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
