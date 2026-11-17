package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"elyrn/internal/config"
	"elyrn/internal/cryptoengine"
	"elyrn/internal/e2e"
	"elyrn/internal/models"

	"github.com/google/uuid"
)

// fileMessage seals, as member 1 of the fixture, a message announcing file with caption text.
func (fx *roomFixture) fileMessage(tb testing.TB, text string, file e2e.File) models.MessageDTO {
	tb.Helper()
	roster := make([]string, len(fx.members))
	for i, m := range fx.members {
		roster[i] = m.Card
	}
	recipients, digest, err := fx.keys.Recipients(fx.members[1], roster)
	if err != nil {
		tb.Fatalf("Recipients: %v", err)
	}
	id := uuid.New()
	blob, err := fx.keys.SealMessageWithFileForTesting(fx.members[1], id, recipients, digest, text, fuzzSentAtMillis, 1, file)
	if err != nil {
		tb.Fatalf("SealMessageWithFileForTesting: %v", err)
	}
	return models.MessageDTO{ID: id.String(), Seq: 1, Ciphertext: blob}
}

func randomFile(tb testing.TB, name string, size int64) e2e.File {
	tb.Helper()
	key, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
	if err != nil {
		tb.Fatalf("RandomBytes: %v", err)
	}
	hash, err := cryptoengine.RandomBytes(cryptoengine.AES256KeySize)
	if err != nil {
		tb.Fatalf("RandomBytes: %v", err)
	}
	return e2e.File{ID: uuid.New(), Key: key, Size: size, Hash: hash, Name: name}
}

func openOnePage(fx *roomFixture, dto models.MessageDTO) []Message {
	st := fx.state()
	return st.openPage([]models.MessageDTO{dto}, st.forwardWindow(0, newLedger(st.counters))).messages
}

func TestFileMessage_ShowsTextNameAndSizeOnly(t *testing.T) {
	fx := newRoomFixture(t)
	file := randomFile(t, "rapor ✓.pdf", config.MaxFileBytesBound)
	got := openOnePage(fx, fx.fileMessage(t, "see attached", file))
	if len(got) != 1 || got[0].Broken || got[0].Text != "see attached" || got[0].File == nil ||
		*got[0].File != (FileInfo{Name: file.Name, Size: file.Size}) {
		t.Fatalf("the file message read as %+v", got)
	}
	shown, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for what, secret := range map[string]string{
		"key": base64.RawURLEncoding.EncodeToString(file.Key), "hash": base64.RawURLEncoding.EncodeToString(file.Hash),
		"id": file.ID.String(),
	} {
		if bytes.Contains(shown, []byte(secret)) {
			t.Fatalf("the result carries the file's %s", what)
		}
	}
	if caption := openOnePage(fx, fx.fileMessage(t, "", randomFile(t, "a.png", 1))); len(caption) != 1 || caption[0].Broken ||
		caption[0].Text != "" || caption[0].File == nil {
		t.Fatalf("a file without a caption read as %+v", caption)
	}
	plain := openOnePage(fx, fx.dto(servedItem{entry: 0, seq: 1}))
	if len(plain) != 1 || plain[0].Broken || plain[0].File != nil {
		t.Fatalf("a message without a file read as %+v", plain)
	}
}

// A file whose description breaks the rule is a broken message: nothing of it is shown.
func TestFileMessage_AgainstTheRuleIsBroken(t *testing.T) {
	fx := newRoomFixture(t)
	for name, file := range map[string]e2e.File{
		"hidden name":     randomFile(t, ".env", 1),
		"path in name":    randomFile(t, "../a.png", 1),
		"bidi in name":    randomFile(t, "gpj.‮exe", 1),
		"empty file":      randomFile(t, "a.png", 0),
		"too large":       randomFile(t, "a.png", config.MaxFileBytesBound+1),
		"short key":       {ID: uuid.New(), Key: make([]byte, 31), Size: 1, Hash: make([]byte, 32), Name: "a"},
		"not a UUIDv4 id": {ID: uuid.Nil, Key: make([]byte, 32), Size: 1, Hash: make([]byte, 32), Name: "a"},
	} {
		got := openOnePage(fx, fx.fileMessage(t, "caption", file))
		if len(got) != 1 || !got[0].Broken || got[0].Text != "" || got[0].File != nil {
			t.Errorf("%s: read as %+v", name, got)
		}
	}
}
