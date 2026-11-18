package e2e

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"elyrn/internal/config"

	"github.com/google/uuid"
)

// Fixed parts of the file payloads below (the Go vector's file, vectors-go.json).
const (
	goFileID      = "6f1e2d3c-4b5a-4968-8776-655443322110"
	goFileKey     = "gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8" // bytes 0x80..0x9f
	goFileHash    = "Qf1qQZSwVj77ObdHVoZ3fA9IjpCzJotXNZoKn9TrcbA" // SHA-256("elyrn. file vector\n")
	goFileSize    = int64(19)
	goFileName    = "résumé ✓ 2026.pdf"
	goFileCounter = int64(7)
	goFileMessage = "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f"
	// Sealed by Go as A for the roster (A's Go card, browserCardB); A and B must open it
	goFileBlob = "TkFEUgFquyEiXuBSLXphcUiSIPe49fWzOCk8ZJ9RxrvMz2msPv2O3ssysYu0kWsIKymKuOzbMzeRdMirMZMCvvkvYFS79KBE05cX5RgDjCCDI8ZpIVaBdWdr3PYnx_FtQrEjbLY82niKJC--e-SmoX19qlNUFzDdqyn2E4P5G2gurY2XhiNT1PYrt4apDcIl8OomFadeymkaebE4Hsvi2vQCKeXwcIwCj3L6GccJBaOvOIPD_i2Sf2IHp8K_eIVvw006rVPDq4XU-sOkwlbavK9OhT9IoSVPY-LaGtcMqryBkB94B9m_wGLscIaUwFry8bT2VzP7tWp2Jxq9R-dKfu5tToNs3nDkhIn-F1LBUJ8Vf0PWOO8MGfAvXDLtAbg2N3iQeyvqWVtB64aetdsoYKFSFxHoz3YxoN6zEwbWPGfi-ldhTH-ulR_Qzk47nZW0giBj_5Ew0vCP6VvnDHu0NY66lJTmhQGlBPogxhUIajHIow-c4ieUVTgKcpZ7gN7ywEGPCXGsV4fPhc9iWrB7hN4e9BV0S6iWvIKoSauFCT_gAvqghvHSF0yIoIoooOf5eWxfnvJ9RxE1U6KFsF5SFmeCitiUuwgeMWLrvASeCAIlnSBYQvkQ0XZCOCKvWX5CI2PyPd8qRlD8VhC1UEN8mfE3YvWrzgGyBTZk-1MXoPQrkFvdWDVw1VemjgyB8JUH8F8"
	// goFilePayload is the payload JSON.stringify writes for that message
	goFilePayload = `{"t":"","ts":1729700000000,"n":7,"f":{"i":"6f1e2d3c-4b5a-4968-8776-655443322110","k":"gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp8","s":19,"h":"Qf1qQZSwVj77ObdHVoZ3fA9IjpCzJotXNZoKn9TrcbA","n":"résumé ✓ 2026.pdf"}}`
)

// jsonObject writes the fields of base, overridden by changes (field name → raw JSON value; ""
// drops the field), in the order given.
func jsonObject(order []string, base, changes map[string]string) string {
	fields := make(map[string]string, len(base))
	for k, v := range base {
		fields[k] = v
	}
	for k, v := range changes {
		fields[k] = v
	}
	var out []string
	for _, k := range order {
		if v, ok := fields[k]; ok && v != "" {
			out = append(out, `"`+k+`":`+v)
		}
	}
	return "{" + strings.Join(out, ",") + "}"
}

// fileObjectJSON is the vector's "f", changed as asked.
func fileObjectJSON(changes map[string]string) string {
	return jsonObject([]string{"i", "k", "s", "h", "n", "x"}, map[string]string{"i": `"` + goFileID + `"`, "k": `"` + goFileKey + `"`,
		"s": strconv.FormatInt(goFileSize, 10), "h": `"` + goFileHash + `"`, "n": `"` + goFileName + `"`}, changes)
}

// filePayloadJSON is a payload with a caption and the vector's "f", its top level and "f" changed as asked.
func filePayloadJSON(top, f map[string]string) string {
	return jsonObject([]string{"t", "ts", "n", "f", "x"}, map[string]string{"t": `"caption"`,
		"ts": strconv.FormatInt(vectorSentAt, 10), "n": "1", "f": fileObjectJSON(f)}, top)
}

func decodeJSONPayload(t *testing.T, body string) (*Message, error) {
	t.Helper()
	framed, err := frame([]byte(body))
	if err != nil {
		t.Fatalf("frame: %v", err)
	}
	return decodePayload(framed)
}

func TestPayload_TheEncoderNeverEmitsAFile(t *testing.T) {
	framed, err := encodePayload(vectorText, vectorSentAt, vectorCounter)
	if err != nil {
		t.Fatalf("encodePayload: %v", err)
	}
	body, err := unframe(framed)
	if err != nil {
		t.Fatalf("unframe: %v", err)
	}
	if want := `{"t":"noaddx. interop ✓ <b>&","ts":1729700000000,"n":3}`; string(body) != want {
		t.Fatalf("payload bytes %s, want %s", body, want)
	}
}

func TestFilePayload_IsReadFieldByField(t *testing.T) {
	msg, err := decodeJSONPayload(t, goFilePayload)
	if err != nil {
		t.Fatalf("decodePayload: %v", err)
	}
	f := msg.File
	if f == nil || msg.Text != "" || msg.Counter != goFileCounter || f.ID != uuid.MustParse(goFileID) || f.Size != goFileSize ||
		encode(f.Key) != goFileKey || encode(f.Hash) != goFileHash || f.Name != goFileName {
		t.Fatalf("decoded %+v %+v", msg, f)
	}
	largest := strconv.FormatInt(config.MaxFileBytesBound, 10)
	for name, body := range map[string]string{
		"caption":            filePayloadJSON(nil, nil),
		"largest size":       filePayloadJSON(nil, map[string]string{"s": largest}),
		"one byte":           filePayloadJSON(nil, map[string]string{"s": "1"}),
		"longest name":       filePayloadJSON(nil, map[string]string{"n": `"` + strings.Repeat("𝒜", FileNameMaxChars) + `"`}),
		"inner dot and dash": filePayloadJSON(nil, map[string]string{"n": `"a.b-c_d (1).tar.gz"`}),
		"escaped name":       filePayloadJSON(nil, map[string]string{"n": `"été.png"`}),
	} {
		if msg, err := decodeJSONPayload(t, body); err != nil || msg.File == nil {
			t.Errorf("%s: %s refused (%v)", name, body, err)
		}
	}
	if msg, err := decodeJSONPayload(t, `{"t":"plain","ts":1729700000000,"n":2}`); err != nil || msg.File != nil {
		t.Fatalf("a payload without f: %+v %v", msg, err)
	}
}

func TestFilePayload_EverythingElseIsRefused(t *testing.T) {
	short := `"` + goFileKey[:len(goFileKey)-1] + `"`
	tooBig := strconv.FormatInt(config.MaxFileBytesBound+1, 10)
	cases := map[string]string{
		"f missing a key":         filePayloadJSON(nil, map[string]string{"h": ""}),
		"f with a sixth key":      filePayloadJSON(nil, map[string]string{"x": "1"}),
		"f null":                  filePayloadJSON(map[string]string{"f": "null"}, nil),
		"f a string":              filePayloadJSON(map[string]string{"f": `"file"`}, nil),
		"f an array":              filePayloadJSON(map[string]string{"f": `[]`}, nil),
		"f empty":                 filePayloadJSON(map[string]string{"f": `{}`}, nil),
		"another fourth key":      filePayloadJSON(map[string]string{"f": "", "x": "1"}, nil),
		"five keys":               filePayloadJSON(map[string]string{"x": "1"}, nil),
		"no t":                    filePayloadJSON(map[string]string{"t": ""}, nil),
		"no n":                    filePayloadJSON(map[string]string{"n": ""}, nil),
		"t not a string":          filePayloadJSON(map[string]string{"t": "1"}, nil),
		"id uppercase":            filePayloadJSON(nil, map[string]string{"i": `"` + strings.ToUpper(goFileID) + `"`}),
		"id version 1":            filePayloadJSON(nil, map[string]string{"i": `"6f1e2d3c-4b5a-1968-8776-655443322110"`}),
		"id braced":               filePayloadJSON(nil, map[string]string{"i": `"{` + goFileID + `}"`}),
		"id nil":                  filePayloadJSON(nil, map[string]string{"i": `"00000000-0000-0000-0000-000000000000"`}),
		"key short":               filePayloadJSON(nil, map[string]string{"k": short}),
		"key long":                filePayloadJSON(nil, map[string]string{"k": `"` + goFileKey + `A"`}),
		"key non-canonical":       filePayloadJSON(nil, map[string]string{"k": `"` + goFileKey[:len(goFileKey)-1] + `9"`}),
		"key standard base64":     filePayloadJSON(nil, map[string]string{"k": `"` + base64.StdEncoding.EncodeToString(mustDecode(t, goFileKey)) + `"`}),
		"hash short":              filePayloadJSON(nil, map[string]string{"h": short}),
		"hash number":             filePayloadJSON(nil, map[string]string{"h": "1"}),
		"size zero":               filePayloadJSON(nil, map[string]string{"s": "0"}),
		"size negative":           filePayloadJSON(nil, map[string]string{"s": "-1"}),
		"size over the bound":     filePayloadJSON(nil, map[string]string{"s": tooBig}),
		"size fractional":         filePayloadJSON(nil, map[string]string{"s": "1.5"}),
		"size exponent":           filePayloadJSON(nil, map[string]string{"s": "1e3"}),
		"size string":             filePayloadJSON(nil, map[string]string{"s": `"19"`}),
		"name empty":              filePayloadJSON(nil, map[string]string{"n": `""`}),
		"name too long":           filePayloadJSON(nil, map[string]string{"n": `"` + strings.Repeat("a", FileNameMaxChars+1) + `"`}),
		"name with a slash":       filePayloadJSON(nil, map[string]string{"n": `"a/b.png"`}),
		"name with a backslash":   filePayloadJSON(nil, map[string]string{"n": `"a\\b.png"`}),
		"name hidden":             filePayloadJSON(nil, map[string]string{"n": `".bashrc"`}),
		"name parent":             filePayloadJSON(nil, map[string]string{"n": `".."`}),
		"name with a NUL":         filePayloadJSON(nil, map[string]string{"n": `"a\u0000b"`}),
		"name with a newline":     filePayloadJSON(nil, map[string]string{"n": `"a\nb"`}),
		"name with DEL":           filePayloadJSON(nil, map[string]string{"n": "\"a\u007fb\""}),
		"name with a C1 control":  filePayloadJSON(nil, map[string]string{"n": "\"a\u0085b\""}),
		"name with RLO":           filePayloadJSON(nil, map[string]string{"n": "\"gpj.‮exe\""}),
		"name with an isolate":    filePayloadJSON(nil, map[string]string{"n": "\"a⁦b\""}),
		"name with RLM":           filePayloadJSON(nil, map[string]string{"n": "\"a‏b\""}),
		"name with ALM":           filePayloadJSON(nil, map[string]string{"n": "\"a؜b\""}),
		"name not NFC":            filePayloadJSON(nil, map[string]string{"n": "\"über.txt\""}),
		"name not a string":       filePayloadJSON(nil, map[string]string{"n": "7"}),
		"no ts":                   filePayloadJSON(map[string]string{"ts": ""}, nil),
		"three keys, one is f":    `{"ts":1729700000000,"n":1,"f":` + fileObjectJSON(nil) + `}`,
		"a plain payload with x":  `{"t":"a","ts":1729700000000,"n":1,"x":1}`,
		"a plain payload, 2 keys": `{"t":"a","ts":1729700000000}`,
	}
	for name, body := range cases {
		if msg, err := decodeJSONPayload(t, body); err == nil {
			t.Errorf("%s: %s accepted as %+v", name, body, msg)
		}
	}
}

func TestFileMessageInterop_GoVectors(t *testing.T) {
	v := loadVectorRoom(t)
	for name, reader := range map[string]roomParty{"a": v.a, "b": v.b} {
		msg, err := v.room.OpenMessage(reader.member, uuid.MustParse(goFileMessage), goFileBlob)
		if err != nil {
			t.Fatalf("%s: OpenMessage(Go file vector): %v", name, err)
		}
		f := msg.File
		if f == nil || msg.Text != "" || msg.SentAt != vectorSentAt || msg.Counter != goFileCounter || !bytes.Equal(msg.Sender, v.a.member.Public) ||
			f.ID != uuid.MustParse(goFileID) || encode(f.Key) != goFileKey || f.Size != goFileSize || encode(f.Hash) != goFileHash || f.Name != goFileName {
			t.Fatalf("%s opened %+v %+v", name, msg, f)
		}
	}
	if _, err := v.room.OpenMessage(v.c.member, uuid.MustParse(goFileMessage), goFileBlob); err == nil {
		t.Fatal("a member outside the roster opened the file vector")
	}
}

// Browser → Go file message (vectors-js.json): sealed by frontend/js as A for the roster (A's Go
// card, browserCardB) with random keys; the blob is randomised, so it is opened, never compared.
const (
	browserFileMessage = "d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f60"
	browserFileText    = "browser caption"
	browserFileCounter = int64(9)
	browserFileID      = "2799a35e-9f0f-4983-b212-806a2c83f879"
	browserFileKey     = "JHkOgVUpgYuykvVknQOl80DQ1F7hvqLL1Qexe3N_tTs"
	browserFileSize    = int64(31)
	browserFileHash    = "pthK7fLenrIIL83EwvEtz5MsXnJijZvO8EIkQsSAbqI"
	browserFileName    = "file-7683b7a5.txt"
	browserFileBlob    = "TkFEUgFquyEiXuBSLXphcUiSIPe49fWzOCk8ZJ9RxrvMz2msPv2O3ssysYu0kWsIKymKuOzbMzeRdMirMZMCvvmk30fnVaSsLTy5FzhetKu7HOiPlqjOeDbwIy1gj5LFOjZLEJxQPDWC7efY6l7INkfO4MI98UIxYdv0RQkOncRIrY2XhiNT1PYrt4apDcIl8OomFadeymkaebE4Hsvi2vQCNbJ1p8umD8QG_hZBDOeXrmuHjUE9vGTJPZWYWXnLY0fhn6uWHAB3QKr3poqiq2PT8q_drHVh442oXNp2CSgG-jQ_65gQbTIxl4Z5EoTQ5vy1l8rO7WKuSatd4GVwaY0sc2u1cNuhvLDf9KYGiDyIpUYaVwR31LudPd2lmgJNqFWRyHtDJcxp44f5g0Hjo4fLCcFE4WdZ1i0QseXS_0HtZs8nJqAHHEWABzKbjPu4UpMRc59hwpxPfypUGot7ETAbH-QNjQwSkx7er79NJNosDAVgvLaGb8R9lHOZUSXfYG5XW2WkRnf75tyaMflHBnzdC9CfATv4pkeNgsQ-8jHMu52LGVXqk_0ZU-K8aPojYSEGWTQELflBBYA1-ej7fcDGQs-6jPrkEuXGjnyJXgYTu2rFf0tNlhH8KAaUxQcK0cMEwCVbDq67HyWK5iZJyYs3K4J4cf7S2Mlzke4Qho33kaZs69rQN5YIS4mH8qsT0Ls"
)

func TestFileMessageInterop_OpensWhatTheBrowserSealed(t *testing.T) {
	v := loadVectorRoom(t)
	for name, reader := range map[string]roomParty{"a": v.a, "b": v.b} {
		msg, err := v.room.OpenMessage(reader.member, uuid.MustParse(browserFileMessage), browserFileBlob)
		if err != nil {
			t.Fatalf("%s: OpenMessage(browser file vector): %v", name, err)
		}
		f := msg.File
		if f == nil || msg.Text != browserFileText || msg.SentAt != vectorSentAt || msg.Counter != browserFileCounter || !bytes.Equal(msg.Sender, v.a.member.Public) ||
			f.ID != uuid.MustParse(browserFileID) || encode(f.Key) != browserFileKey || f.Size != browserFileSize || encode(f.Hash) != browserFileHash || f.Name != browserFileName {
			t.Fatalf("%s opened %+v %+v", name, msg, f)
		}
	}
	if _, err := v.room.OpenMessage(v.c.member, uuid.MustParse(browserFileMessage), browserFileBlob); err == nil {
		t.Fatal("a member outside the roster opened the browser file vector")
	}
}

// The test-only sealer writes exactly the vector's payload bytes for the vector's file.
func TestFilePayload_TestSealerWritesTheVectorBytes(t *testing.T) {
	file := File{ID: uuid.MustParse(goFileID), Key: mustDecode(t, goFileKey), Size: goFileSize, Hash: mustDecode(t, goFileHash), Name: goFileName}
	framed, err := framePayload(payload{T: "", TS: vectorSentAt, N: goFileCounter, F: file.wire()})
	if err != nil {
		t.Fatalf("framePayload: %v", err)
	}
	body, err := unframe(framed)
	if err != nil || string(body) != goFilePayload {
		t.Fatalf("payload %s (%v), want %s", body, err, goFilePayload)
	}
}

// FuzzFilePayload: any payload body is either refused or read as exactly the three fields, or
// the three and an "f" whose every field is in range; the encoder's own payloads still read back.
func FuzzFilePayload(f *testing.F) {
	for _, seed := range []string{goFilePayload, filePayloadJSON(nil, nil), filePayloadJSON(nil, map[string]string{"s": "0"}),
		filePayloadJSON(nil, map[string]string{"n": `".x"`}), filePayloadJSON(map[string]string{"f": "null"}, nil),
		`{"t":"a","ts":1,"n":1}`, `{"t":"a","ts":1,"n":1,"f":{}}`, `{"t":"","ts":1,"n":1,"x":{}}`, "", "{", "null"} {
		f.Add([]byte(seed), "caption", int64(1))
	}
	f.Fuzz(func(t *testing.T, body []byte, text string, counter int64) {
		if framed, err := frame(body); err == nil {
			if msg, err := decodePayload(framed); err == nil {
				checkDecodedPayload(t, body, msg)
			}
		}
		framed, err := encodePayload(text, vectorSentAt, counter)
		if err != nil {
			return
		}
		msg, err := decodePayload(framed)
		if err != nil || msg.File != nil || msg.Counter != counter || msg.SentAt != vectorSentAt ||
			(utf8.ValidString(text) && msg.Text != text) {
			t.Fatalf("the encoder's payload for %q did not read back: %+v %v", text, msg, err)
		}
	})
}

// checkDecodedPayload fails unless msg is in range: a positive time and counter, and a file
// (if any) whose fields hold the rule.
func checkDecodedPayload(t *testing.T, body []byte, msg *Message) {
	t.Helper()
	if msg.SentAt <= 0 || msg.Counter < 1 {
		t.Fatalf("%q read with time %d, counter %d", body, msg.SentAt, msg.Counter)
	}
	file := msg.File
	if file == nil {
		return
	}
	if file.ID.Version() != 4 || len(file.Key) != fileKeySize || len(file.Hash) != fileHashSize ||
		file.Size < fileMinSize || file.Size > config.MaxFileBytesBound || !fileNameValid(file.Name) {
		t.Fatalf("%q read as the file %+v", body, file)
	}
}
