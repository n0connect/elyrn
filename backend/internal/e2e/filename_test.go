package e2e

import (
	"encoding/json"
	"strings"
	"testing"
)

// The file-name cases shared with the browser (vectors-js.json file_names, validation.js
// isFileName): since 18 Nov both readers also refuse every format character (Unicode Cf) and two
// or more space characters (Unicode Zs) in a row, beside the rules before.
var (
	sharedFileNamesAccepted = []string{
		"a", "r\u00e9sum\u00e9 \u2713 2026.pdf", strings.Repeat("x", FileNameMaxChars), "\u65e5\u672c\u8a9e\u306e\u66f8\u985e.txt",
		strings.Repeat("\u00e9", FileNameMaxChars), "a.b.c", "name.", "-dash", "no\u00a0break",
		strings.Repeat("\U0001f642", FileNameMaxChars), "C:drive.txt", "a<b>.txt", "\u00c5.txt", "a b c.txt",
		" lead and trail ", "ideographic\u3000space", "thin\u2009space",
	}
	sharedFileNamesRefused = []string{
		"", ".env", "..", ".", "a/b", "a\\b", strings.Repeat("x", FileNameMaxChars+1),
		strings.Repeat("\U0001f642", FileNameMaxChars+1), strings.Repeat("\U0001f642", FileNameMaxChars-1) + "ab",
		"a\x00b", "a\nb", "a\tb", "del\x7f", "c1\u0085", "pay\u202etxt.exe", "a\u2066b", "lrm\u200e",
		"alm\u061c", "e\u0301.txt", "A\u030a.txt", "\u212b.txt", "zero\u200bwidth.txt", "join\u200dme",
		"non\u200cjoin", "word\u2060joiner", "bom\ufeff.txt", "soft\u00adhyphen", "mongolian\u180evowel",
		"tag\U000e0041.txt", "arabic\u0600number", "two  spaces.txt", "gap\u00a0\u00a0wide",
		"mixed \u00a0run", "wide\u3000\u3000gap", "  lead", "trail  ",
	}
)

func TestFileName_SharedCasesWithTheBrowser(t *testing.T) {
	for _, name := range sharedFileNamesAccepted {
		if !fileNameValid(name) {
			t.Errorf("%+q refused; the browser accepts it", name)
		}
	}
	for _, name := range sharedFileNamesRefused {
		if fileNameValid(name) {
			t.Errorf("%+q accepted; the browser refuses it", name)
		}
	}
	// The same verdict through a whole payload: a message naming a refused file does not open
	for _, name := range sharedFileNamesRefused {
		quoted, err := json.Marshal(name)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := decodeJSONPayload(t, filePayloadJSON(nil, map[string]string{"n": string(quoted)})); err == nil {
			t.Errorf("a payload naming the file %+q opened", name)
		}
	}
}
