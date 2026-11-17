package handlers

import (
	"net/http"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/chat"
	"elyrn/internal/models"
	"elyrn/internal/realtime"
	"elyrn/internal/utils"
)

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

// setRole stores a sealed role and tells every member, the caller's other devices included.
func setRole(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	if !allowOrTooMany(w, bucketRole, me) {
		return
	}
	var req models.SetRoleRequest
	if !bindInput(w, r, &req, "setRole") {
		return
	}
	streams, err := svc.SetRole(me, id, req.Card, req.Role)
	if err != nil {
		apperr.WriteError(w, "SetRole", err)
		return
	}
	realtime.Default.Publish(streams, realtime.Event{Kind: realtime.KindConversation})
	w.WriteHeader(http.StatusNoContent)
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
