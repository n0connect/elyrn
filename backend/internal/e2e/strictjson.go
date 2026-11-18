package e2e

// The exact JSON reader of authenticated payloads (audit F3,
// backend/internal/e2e/e2e.go:decodePayload:go-json-lenient-keys-and-utf8-vs-browser-strict).
// encoding/json binds a struct field to a key that only case-folds to its tag ("T" for "t", the
// Kelvin sign for "k") and, under the default options of Go 1.27 (jsonv2) as under the legacy
// decoder, turns invalid UTF-8 and a lone surrogate escape into U+FFFD. The browser
// (crypto.js decodePayload, fileFrom) reads the frame with a fatal UTF-8 decoder and takes the
// exact keys, so such a payload was a message to the agent and unreadable to every person. Here
// keys are compared byte for byte after JSON unescaping, values are read from the exact entries
// only, and the bytes are checked before any decoder sees them: whichever decoder is built in,
// nothing it would relax is ever left to it.
//
// Duplicate keys: the browser's JSON.parse keeps the last value of a repeated key, so this
// reader does the same (explicitly, not by the decoder's options): refusing them would make a
// payload a message to people and unreadable to the agent, the divergence this file closes.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER: the browser refuses any ts, n or s
	// above it (Number.isSafeInteger)
	maxSafeInteger = int64(1)<<53 - 1

	jsonQuote       = '"'
	jsonBackslash   = '\\'
	jsonEscapeU     = 'u'
	jsonMinus       = '-'
	jsonHexDigits   = 4
	jsonObjectOpen  = '{'
	jsonObjectClose = '}'

	surrogateHighFirst = 0xD800
	surrogateHighLast  = 0xDBFF
	surrogateLowFirst  = 0xDC00
	surrogateLowLast   = 0xDFFF
	hexBits            = 4
	hexLetterValue     = 10 // the value of hex digit a/A
)

var errNotExact = errors.New("e2e: payload JSON is not exact")

// exactObject reads raw as exactly one JSON object and returns its members by their exact,
// unescaped keys (the last of a repeated key wins, as in JSON.parse). raw must be valid UTF-8
// with no lone surrogate escape anywhere; anything else, trailing data included, is refused.
func exactObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) || hasLoneSurrogateEscape(raw) {
		return nil, errNotExact
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := decoder.Token(); err != nil || tok != json.Delim(jsonObjectOpen) {
		return nil, errNotExact
	}
	members := make(map[string]json.RawMessage)
	for decoder.More() {
		tok, err := decoder.Token()
		key, isKey := tok.(string)
		if err != nil || !isKey {
			return nil, errNotExact
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errNotExact
		}
		members[key] = value
	}
	if tok, err := decoder.Token(); err != nil || tok != json.Delim(jsonObjectClose) {
		return nil, errNotExact
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errNotExact
	}
	return members, nil
}

// exactString is a JSON string value (never null, a number or anything else), unescaped.
func exactString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != jsonQuote || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// exactSafeInteger is a JSON integer literal within JavaScript's safe integers. A fraction or an
// exponent (1.0, 1e3) is refused although JSON.parse would read a whole number from it: the
// known limit recorded in docs/architecture/agents.md (Go is stricter there, never laxer).
func exactSafeInteger(raw json.RawMessage) (int64, bool) {
	var n int64
	if len(raw) == 0 || !(raw[0] == jsonMinus || (raw[0] >= '0' && raw[0] <= '9')) || json.Unmarshal(raw, &n) != nil ||
		n > maxSafeInteger || n < -maxSafeInteger {
		return 0, false
	}
	return n, true
}

// hasLoneSurrogateEscape reports whether a string in raw holds a \uD800..\uDFFF escape that is
// not a high surrogate escape directly followed by a low one. Raw invalid UTF-8 is refused before
// (utf8.Valid); malformed escapes are left to the decoder, which refuses them.
func hasLoneSurrogateEscape(raw []byte) bool {
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case !inString:
			inString = c == jsonQuote
		case c == jsonQuote:
			inString = false
		case c == jsonBackslash:
			unit, ok := escapedUnit(raw, i)
			if !ok {
				i++ // a one-character escape (or a malformed one the decoder refuses)
				continue
			}
			i += 1 + jsonHexDigits
			switch {
			case unit >= surrogateLowFirst && unit <= surrogateLowLast:
				return true
			case unit >= surrogateHighFirst && unit <= surrogateHighLast:
				low, ok := escapedUnit(raw, i+1)
				if !ok || low < surrogateLowFirst || low > surrogateLowLast {
					return true
				}
				i += 2 + jsonHexDigits
			}
		}
	}
	return false
}

// escapedUnit reads the \uXXXX escape starting at raw[at] (the backslash), if it is one.
func escapedUnit(raw []byte, at int) (rune, bool) {
	if at+1+jsonHexDigits >= len(raw) || raw[at] != jsonBackslash || raw[at+1] != jsonEscapeU {
		return 0, false
	}
	var unit rune
	for _, h := range raw[at+2 : at+2+jsonHexDigits] {
		var digit rune
		switch {
		case h >= '0' && h <= '9':
			digit = rune(h - '0')
		case h >= 'a' && h <= 'f':
			digit = rune(h-'a') + hexLetterValue
		case h >= 'A' && h <= 'F':
			digit = rune(h-'A') + hexLetterValue
		default:
			return 0, false
		}
		unit = unit<<hexBits | digit
	}
	return unit, true
}
