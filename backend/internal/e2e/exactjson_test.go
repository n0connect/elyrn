package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// F3 (backend/internal/e2e/e2e.go:decodePayload:go-json-lenient-keys-and-utf8-vs-browser-strict):
// the Go reader takes exactly what crypto.js decodePayload and fileFrom take. Each case below
// names the browser behaviour it matches; every refused case was a message to the agent before
// (encoding/json folds key case and replaces bad UTF-8 and lone surrogates with U+FFFD).

const exactTime = `"ts":1729700000000`

func TestExactReader_RefusesWhatTheBrowserRefuses(t *testing.T) {
	for name, body := range map[string]string{
		// crypto.js requires the exact lowercase keys (hasOwnProperty)
		"T for t":                              `{"T":"x",` + exactTime + `,"n":1}`,
		"TS for ts":                            `{"t":"x","TS":1729700000000,"n":1}`,
		"N for n":                              `{"t":"x",` + exactTime + `,"N":1}`,
		"F for f":                              `{"t":"x",` + exactTime + `,"n":1,"F":` + fileObjectJSON(nil) + `}`,
		"N for the file's n":                   strings.Replace(goFilePayload, `"n":"r`, `"N":"r`, 1),
		"Kelvin sign for the file's k":         strings.Replace(goFilePayload, `"k":`, "\"\u212a\":", 1),
		"Kelvin sign escaped for the file's k": strings.Replace(goFilePayload, `"k":`, `"\u212a":`, 1),
		"long s for the file's s":              strings.Replace(goFilePayload, `"s":`, "\"\u017f\":", 1),
		// TextDecoder('utf-8', {fatal: true}) throws on invalid UTF-8 anywhere in the frame
		"raw 0xFF in t":          "{\"t\":\"a\xffb\"," + exactTime + `,"n":1}`,
		"raw 0xFF in the name":   filePayloadJSON(nil, map[string]string{"n": "\"a\xff.txt\""}),
		"overlong encoding in t": "{\"t\":\"\xc0\xaf\"," + exactTime + `,"n":1}`,
		"encoded surrogate in t": "{\"t\":\"\xed\xa0\x80\"," + exactTime + `,"n":1}`,
		// a lone surrogate escape: refused here (isFileName refuses it in a name; in a text the
		// browser would show a broken character, Go refuses the message: stricter, never laxer)
		"lone high escape in the name": filePayloadJSON(nil, map[string]string{"n": `"\ud800a.txt"`}),
		"lone low escape in t":         `{"t":"\udc00",` + exactTime + `,"n":1}`,
		"high escape then a letter":    `{"t":"\ud800\u0041",` + exactTime + `,"n":1}`,
		"high escape at the end":       `{"t":"a\ud83d",` + exactTime + `,"n":1}`,
		"two high escapes":             `{"t":"\ud83d\ud83d",` + exactTime + `,"n":1}`,
		// typeof t === 'string', Number.isSafeInteger(ts), Number.isSafeInteger(n)
		"t null":                     `{"t":null,` + exactTime + `,"n":1}`,
		"ts null":                    `{"t":"x","ts":null,"n":1}`,
		"n null":                     `{"t":"x",` + exactTime + `,"n":null}`,
		"ts above the safe integers": `{"t":"x","ts":9007199254740992,"n":1}`,
		"n above the safe integers":  `{"t":"x",` + exactTime + `,"n":9007199254740992}`,
		"s above the safe integers":  filePayloadJSON(nil, map[string]string{"s": "9007199254740992"}),
		"the name null":              filePayloadJSON(nil, map[string]string{"n": "null"}),
		"the id null":                filePayloadJSON(nil, map[string]string{"i": "null"}),
		"s null":                     filePayloadJSON(nil, map[string]string{"s": "null"}),
		// JSON.parse refuses anything after the value
		"trailing data":   `{"t":"x",` + exactTime + `,"n":1} x`,
		"a second object": `{"t":"x",` + exactTime + `,"n":1}{}`,
		"not an object":   `["t","ts","n"]`,
	} {
		if msg, err := decodeJSONPayload(t, body); err == nil {
			t.Errorf("%s: %q accepted as %+v", name, body, msg)
		}
	}
}

func TestExactReader_AcceptsWhatTheBrowserAccepts(t *testing.T) {
	for name, tc := range map[string]struct{ body, text string }{
		// JSON.parse keeps the last value of a repeated key, and so does this reader
		"repeated key, last wins": {`{"t":"first","t":"second",` + exactTime + `,"n":1}`, "second"},
		// an escaped key is the key it spells
		"escaped key": {`{"\u0074":"x",` + exactTime + `,"n":1}`, "x"},
		// a surrogate pair escape is one character
		"surrogate pair escape":      {`{"t":"\ud83d\ude42",` + exactTime + `,"n":1}`, "🙂"},
		"escaped backslash before u": {`{"t":"\\ud800",` + exactTime + `,"n":1}`, `\ud800`},
		"the largest safe counter":   {`{"t":"x",` + exactTime + `,"n":9007199254740991}`, "x"},
	} {
		msg, err := decodeJSONPayload(t, tc.body)
		if err != nil || msg.Text != tc.text {
			t.Errorf("%s: %q read as %+v, %v; want text %q", name, tc.body, msg, err, tc.text)
		}
	}
}

// FuzzExactObject: the exact reader never panics; what it accepts is valid UTF-8 without a lone
// surrogate escape, and the standard decoder reads the same keys from it.
func FuzzExactObject(f *testing.F) {
	for _, seed := range []string{goFilePayload, `{"T":1}`, `{"t":"\ud800"}`, "{\"t\":\"\xff\"}", `{"a":1,"a":2}`,
		`{"\u0074":1}`, `{"t":"\ud83d\ude42"}`, `{} x`, `{"t":"\\ud800"}`, `{"t":"\ud83d\u`, "", "{"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		members, err := ExactObject(raw)
		if err != nil {
			return
		}
		if !utf8.Valid(raw) || hasLoneSurrogateEscape(raw) {
			t.Fatalf("%q accepted with invalid UTF-8 or a lone surrogate escape", raw)
		}
		var standard map[string]json.RawMessage
		if json.Unmarshal(raw, &standard) != nil || len(standard) != len(members) {
			t.Fatalf("%q: the standard decoder disagrees on the members", raw)
		}
		for key := range members {
			if _, ok := standard[key]; !ok {
				t.Fatalf("%q: key %q is not one the standard decoder reads", raw, key)
			}
		}
	})
}
