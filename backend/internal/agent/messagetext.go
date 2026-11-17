package agent

import (
	"strings"
	"unicode/utf8"

	"elyrn/internal/utils"

	"golang.org/x/text/unicode/norm"
)

// replacementRune stands in for a forbidden character in received text (validation.js
// neutralizeReceivedText).
const replacementRune = '\ufffd'

var crlfNormalizer = strings.NewReplacer("\r\n", "\n", "\r", "\n")

// messageTrimChars is validation.js MESSAGE_TRIM_CHARS, character for character: the only
// characters trimmed from either end of a message, ECMAScript's WhiteSpace and LineTerminator
// (what String.prototype.trim strips). Not Go's unicode.IsSpace: U+0085 is a C1 control and so
// refused (forbiddenRune), and U+200B is content; both are kept at the ends like anywhere else.
const messageTrimChars = "\t\n\v\f\r \u00a0\u1680" +
	"\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" +
	"\u2028\u2029\u202f\u205f\u3000\ufeff"

// forbiddenRune is validation.js FORBIDDEN_TEXT_CHARS: control characters other than \n and \t
// (C0, DEL, C1) and the bidi overrides that could reorder what is shown.
func forbiddenRune(r rune) bool {
	return r <= 0x08 || (r >= 0x0B && r <= 0x1F) || (r >= 0x7F && r <= 0x9F) ||
		(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// ValidateMessageText is validation.js validateMessageText: CRLF normalized, messageTrimChars
// trimmed from both ends, 1..2000 characters, no forbidden character, and no word that reads as
// an account number (containsAccountNumber). It returns the text that will be sent.
func ValidateMessageText(text string) (string, error) {
	if !utf8.ValidString(text) {
		return "", fail(CodeMessageText, nil)
	}
	normalized := strings.Trim(crlfNormalizer.Replace(text), messageTrimChars)
	if n := utf8.RuneCountInString(normalized); n == 0 || n > MaxMessageChars || strings.IndexFunc(normalized, forbiddenRune) >= 0 {
		return "", fail(CodeMessageText, nil)
	}
	if containsAccountNumber(normalized) {
		return "", fail(CodeAccountNumber, nil)
	}
	return normalized, nil
}

// containsAccountNumber is validation.js containsAccountNumber: the text read through Unicode NFKC
// (so a fullwidth or other compatibility look-alike folds to ASCII), split into words at runs of
// ECMAScript white space (the /\s+/u the browser splits on, which is exactly messageTrimChars),
// and any word of the account number's exact shape (utils.ValidateAccountNumber: 43 base64url
// characters, the browser's ACCOUNT_NUMBER_REGEX). An invite or a room code carries its prefix,
// so sharing one is not refused. accountNumberSamples (fuzz_test.go) pins both sides.
func containsAccountNumber(text string) bool {
	words := strings.FieldsFunc(norm.NFKC.String(text), func(r rune) bool {
		return strings.ContainsRune(messageTrimChars, r)
	})
	for _, word := range words {
		if utils.ValidateAccountNumber(word) {
			return true
		}
	}
	return false
}

func neutralize(text string) string {
	return strings.Map(func(r rune) rune {
		if forbiddenRune(r) {
			return replacementRune
		}
		return r
	}, text)
}
