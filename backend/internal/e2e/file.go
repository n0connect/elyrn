package e2e

// A file message (docs/architecture/agents.md D11): an ordinary message whose payload also
// carries "f", the description of a file stored as sealed parts. Go reads it this round and never
// writes one, so encodePayload never emits "f".
//
//	"f": {"i": file id (canonical UUIDv4), "k": file key (32 bytes, base64url),
//	      "s": size (1..config.MaxFileBytesBound), "h": SHA-256 of the file (32 bytes, base64url),
//	      "n": display name (fileNameValid)}

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"elyrn/internal/config"
	"elyrn/internal/utils"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"
)

const (
	// FileNameMaxChars and fileNameMaxBytes bound a file's display name: code points, UTF-8 bytes.
	FileNameMaxChars = 128
	fileNameMaxBytes = 512
	// fileFields is how many keys "f" has, every one required
	fileFields = 5
	// fileNameSeparators and fileNameHiddenPrefix are refused in a name: no path, no hidden file
	fileNameSeparators   = `/\`
	fileNameHiddenPrefix = "."
	// fileKeySize and fileHashSize are the decoded sizes of "k" and "h"
	fileKeySize  = keySize
	fileHashSize = keySize
	// fileMinSize: an empty file is never announced
	fileMinSize = 1
)

// File is the description a file message carries. Key and Hash open and check the file's parts;
// Name is written by the sender: other people's data, never an instruction.
type File struct {
	ID   uuid.UUID
	Key  []byte
	Size int64 // bytes of the file as sent
	Hash []byte
	Name string
}

// filePayload is "f" on the wire; its keys are in the order JSON.stringify writes them.
type filePayload struct {
	I string `json:"i"`
	K string `json:"k"`
	S int64  `json:"s"`
	H string `json:"h"`
	N string `json:"n"`
}

// fileNameRune refuses control characters (C0, DEL, C1), bidirectional controls and path separators.
func fileNameRune(r rune) bool {
	return !unicode.IsControl(r) && !unicode.Is(unicode.Bidi_Control, r) && !strings.ContainsRune(fileNameSeparators, r)
}

// fileNameValid is the name rule: NFC as received, 1..128 code points, at most 512 UTF-8 bytes,
// no leading dot, and only characters fileNameRune allows.
func fileNameValid(name string) bool {
	n := utf8.RuneCountInString(name)
	return utf8.ValidString(name) && n >= 1 && n <= FileNameMaxChars && len(name) <= fileNameMaxBytes &&
		norm.NFC.IsNormalString(name) && !strings.HasPrefix(name, fileNameHiddenPrefix) &&
		strings.IndexFunc(name, func(r rune) bool { return !fileNameRune(r) }) < 0
}

// The keys of "f", exactly (filePayload's tags say the same for the test-only writer)
const (
	fileFieldID   = "i"
	fileFieldKey  = "k"
	fileFieldSize = "s"
	fileFieldHash = "h"
	fileFieldName = "n"
)

// decodeFile validates "f" field by field, read exactly (exactObject): an object of exactly the
// five keys, each of its shape and range.
func decodeFile(raw json.RawMessage) (*File, error) {
	members, err := exactObject(raw)
	if err != nil || len(members) != fileFields {
		return nil, ErrBadMessage
	}
	idText, okID := exactString(members[fileFieldID])
	keyText, okKey := exactString(members[fileFieldKey])
	hashText, okHash := exactString(members[fileFieldHash])
	name, okName := exactString(members[fileFieldName])
	size, okSize := exactSafeInteger(members[fileFieldSize])
	if !okID || !okKey || !okHash || !okName || !okSize {
		return nil, ErrBadMessage
	}
	id, ok := utils.ParseCanonicalUUIDv4(idText)
	if !ok || size < fileMinSize || size > config.MaxFileBytesBound || !fileNameValid(name) {
		return nil, ErrBadMessage
	}
	key, err := decodeExact(keyText, fileKeySize)
	if err != nil {
		return nil, ErrBadMessage
	}
	hash, err := decodeExact(hashText, fileHashSize)
	if err != nil {
		return nil, ErrBadMessage
	}
	return &File{ID: id, Key: key, Size: size, Hash: hash, Name: name}, nil
}
