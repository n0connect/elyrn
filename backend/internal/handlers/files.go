package handlers

import (
	"net/http"

	"github.com/google/uuid"

	"elyrn/internal/apperr"
	"elyrn/internal/chat"
	"elyrn/internal/contract"
	"elyrn/internal/middleware"
	"elyrn/internal/models"
	"elyrn/internal/utils"
)

// uploadFilePart stores one sealed part (201). The part that opens a file pays one token of the
// caller's file bucket; later parts do not. Nothing is published: the message that announces the
// file, sent once every part is stored, tells the members.
func uploadFilePart(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	var req models.UploadFilePartRequest
	if !bindInput(w, r, &req, "uploadFilePart") {
		return
	}
	if req.Part == chat.FirstFilePart && !allowOrTooMany(w, bucketFile, me) {
		return
	}
	// Every stored part also spends one part of the account's in-memory daily budget
	budget := middleware.FileBudget(me.StreamTag)
	if budget == nil {
		// Unusable budget settings (refused at startup, so never in a started server): fail closed
		apperr.Write(w, "uploadFilePart: budget", apperr.FileBudgetSpent)
		return
	}
	if err := svc.UploadFilePart(me, id, req.ID, req.Part, req.Data, budget); err != nil {
		apperr.WriteError(w, "UploadFilePart", err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// readFilePart answers one stored part to a member (the gate admitted exactly one part number).
func readFilePart(w http.ResponseWriter, in *contract.Input, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	part, _ := in.Query(models.QueryPart)
	data, err := svc.ReadFilePart(me, id, in.PathID(contract.PathFile), int(part))
	if err != nil {
		apperr.WriteError(w, "ReadFilePart", err)
		return
	}
	utils.EncodeJSONResponse(w, models.FilePartResponse{Data: data}, http.StatusOK)
}
