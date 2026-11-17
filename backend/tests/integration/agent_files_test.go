package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"elyrn/internal/agent"
	"elyrn/internal/config"
	"elyrn/internal/e2e"
	"elyrn/internal/models"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

// File messages as the robot sees them, through the real server: text plus the file's name and
// size, never its key, hash or id; and /me's file limit checked like the others.

// sayFile sends a file message as a browser member does: an ordinary room message whose payload
// carries the file's description.
func (s *roomSide) sayFile(t *testing.T, text string, counter int64, file e2e.File) {
	t.Helper()
	recipients, digest, err := s.room.Recipients(s.member, s.roster(t))
	if err != nil {
		t.Fatalf("Recipients: %v", err)
	}
	id := newMessageID()
	blob, err := s.room.SealMessageWithFileForTesting(s.member, uuid.MustParse(id), recipients, digest, text, time.Now().UnixMilli(), counter, file)
	if err != nil {
		t.Fatalf("SealMessageWithFileForTesting: %v", err)
	}
	expectStatus(t, s.post(id, blob), http.StatusCreated, "room send with a file")
}

func TestAgent_ReadsAFileMessageAsTextNameAndSize(t *testing.T) {
	mux := setup(t)
	robot, room, carol := agentWithRoom(t, mux, clientServer(t, mux), newIdentityPath(t.TempDir(), "robot"))
	file := e2e.File{ID: uuid.New(), Key: randomBytes(t, 32), Size: config.MaxFileBytesBound, Hash: randomBytes(t, 32), Name: "rapor ✓.pdf"}
	carol.sayFile(t, "see attached", 1, file)
	bare := file
	bare.Name = "foto.png"
	bare.Size = 1
	carol.sayFile(t, "", 2, bare)
	hidden := file
	hidden.Name = ".bashrc"
	carol.sayFile(t, "never shown", 3, hidden)

	got, err := robot.Read(context.Background(), room, nil)
	if err != nil || len(got.Messages) != 3 {
		t.Fatalf("Read = %+v, %v", got, err)
	}
	first, second, third := got.Messages[0], got.Messages[1], got.Messages[2]
	if first.Text != "see attached" || first.File == nil || first.File.Name != file.Name || first.File.Size != file.Size {
		t.Fatalf("the file message read as %+v", first)
	}
	if second.Text != "" || second.Broken || second.File == nil || second.File.Name != "foto.png" || second.File.Size != 1 {
		t.Fatalf("a file without a caption read as %+v", second)
	}
	if !third.Broken || third.Text != "" || third.File != nil {
		t.Fatalf("a file named against the rule read as %+v", third)
	}
	shown, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for what, secret := range map[string][]byte{
		"key": file.Key, "hash": file.Hash, "id": []byte(file.ID.String()),
		"key (base64url)":  []byte(base64.RawURLEncoding.EncodeToString(file.Key)),
		"hash (base64url)": []byte(base64.RawURLEncoding.EncodeToString(file.Hash)),
	} {
		if bytes.Contains(shown, secret) {
			t.Fatalf("the read result carries the file's %s", what)
		}
	}
}

// /me's file_max_bytes is a limit like the others: out of its bounds, no session, and every later
// call checks again; once it is in bounds the agent works.
func TestAgent_AFileLimitOutOfBoundsLeavesNoSession(t *testing.T) {
	mux := setup(t)
	var served atomic.Int64 // 0: the real /me
	served.Store(-1)
	srv := hostileServer(t, mux, func(w http.ResponseWriter, r *http.Request) bool {
		value := served.Load()
		if value == 0 || r.Method != http.MethodGet || r.URL.Path != models.PathMe {
			return false
		}
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		var me models.MeResponse
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &me) != nil {
			t.Errorf("the real /me answered %d", rr.Code)
			return false
		}
		me.FileMaxBytes = value
		for name, values := range rr.Header() {
			w.Header()[name] = values
		}
		w.Header().Del("Content-Length") // the body below is re-encoded
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(&me)
		return true
	})
	robot := newAgent(t, srv.URL, newIdentityPath(t.TempDir(), "robot"))
	ctx := context.Background()
	if _, err := robot.Identity(ctx); agent.CodeOf(err) != agent.CodeServerAnswer {
		t.Fatalf("Identity with file_max_bytes -1: %v, want %s", err, agent.CodeServerAnswer)
	}
	for _, value := range []int64{utils.FilePartBytes - 1, config.MaxFileBytesBound + 1} {
		served.Store(value)
		if _, err := robot.Rooms(ctx); agent.CodeOf(err) != agent.CodeServerAnswer {
			t.Fatalf("file_max_bytes %d: %v, want %s", value, err, agent.CodeServerAnswer)
		}
	}
	served.Store(utils.FilePartBytes) // the lower bound itself is a limit
	if _, err := robot.Rooms(ctx); err != nil {
		t.Fatalf("file_max_bytes %d: %v", int64(utils.FilePartBytes), err)
	}
}
