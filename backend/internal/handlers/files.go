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

// maxConcurrentFileRequests bounds the file part uploads and reads an authenticated caller has
// handled at once. Past the gate one such request holds about 1.6 MB: the decoded body (the
// 342 KiB data string bound into the request), the 256 KiB raw part, the driver's copy of the
// bytea and, on a read, the base64 answer and its JSON encoding (about 342 KiB each). The backend
// container keeps 128 MiB beside the Argon2id slots (scripts/check-hardening.py
// BACKEND_HEADROOM_BYTES) for the runtime, 20 database connections, event streams and the GC;
// 32 x 1.6 MB = 51 MB stays well under half of it.
//
// Before authentication (the gate reads and checks the body first) memory is bounded by nginx,
// the only way in: it buffers a whole body (at most 342k) before it opens the upstream request,
// and its files location admits at most 32 requests at once (limit_conn files, nginx.conf), so
// at most 32 x 342 KiB = 11 MB of bodies reach the gate together. The slot is taken here, after
// the session check, so a caller without an account can never hold one.
const maxConcurrentFileRequests = 32

// noWait: a request over the bound is refused at once, never queued
const noWait = 0

var fileRequestSlots = utils.NewSlots(maxConcurrentFileRequests)

// withFileSlot runs work holding one of the file request slots, released on every path (an
// error, a panic), or answers 503 E_FILE_REQUESTS_BUSY at once when none is free.
func withFileSlot(w http.ResponseWriter, op string, work func()) {
	if err := fileRequestSlots.Acquire(noWait); err != nil {
		apperr.Write(w, op, apperr.FileRequestsBusy)
		return
	}
	defer fileRequestSlots.Release()
	work()
}

// uploadFilePart stores one sealed part (201). The part that opens a file pays one token of the
// caller's file bucket; later parts do not. Nothing is published: the message that announces the
// file, sent once every part is stored, tells the members.
func uploadFilePart(w http.ResponseWriter, r *http.Request, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	withFileSlot(w, "uploadFilePart", func() {
		var req models.UploadFilePartRequest
		if !bindInput(w, r, &req, "uploadFilePart") {
			return
		}
		if req.Part == chat.FirstFilePart && !allowOrTooMany(w, bucketFile, me) {
			return
		}
		// Every stored part also spends one part of the account's in-memory daily budget
		if err := svc.UploadFilePart(me, id, req.ID, req.Part, req.Data, middleware.FileBudgetOf(me.StreamTag)); err != nil {
			apperr.WriteError(w, "UploadFilePart", err)
			return
		}
		w.WriteHeader(http.StatusCreated)
	})
}

// readFilePart answers one stored part to a member (the gate admitted exactly one part number).
func readFilePart(w http.ResponseWriter, in *contract.Input, svc *chat.Service, me *chat.Member, id uuid.UUID) {
	withFileSlot(w, "readFilePart", func() {
		part, _ := in.Query(models.QueryPart)
		data, err := svc.ReadFilePart(me, id, in.PathID(contract.PathFile), int(part))
		if err != nil {
			apperr.WriteError(w, "ReadFilePart", err)
			return
		}
		utils.EncodeJSONResponse(w, models.FilePartResponse{Data: data}, http.StatusOK)
	})
}
