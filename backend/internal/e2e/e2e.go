// Package e2e is the Go implementation of the elyrn. client message protocol, the
// twin of frontend/js/crypto.js. The server never imports it (it only relays ciphertext);
// it exists so Go code can speak the real protocol — integration tests exchange genuine
// ciphertext through the real server, and interop vectors pin both implementations together.
//
//	conversation key = HKDF-SHA256(X25519(priv, peerPub), salt = conversation id, info "noaddx/conv/v1")
//	plaintext        = len(2) || {"t":text,"ts":sentAt,"n":counter} || zero padding to 256..4096 (a power of two)
//	                   (a file message adds "f", file.go: read here, never written)
//	AAD              = "NADM" || 0x01 || conversation id(16) || message id(16) || SHA-256(sender public key)(32)
//	wire             = base64url(nonce(12) || AES-256-GCM ciphertext || tag(16))
package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"elyrn/internal/cryptoengine"
	"elyrn/internal/utils"

	"github.com/google/uuid"
)

const (
	keySize         = 32
	padBlock        = 256 // smallest frame; frames double from here up to maxFrameBytes
	maxFrameBytes   = 4096
	maxPayloadBytes = maxFrameBytes - 2
	// "noaddx" in these labels is the protocol namespace, not the product name: it never changes.
	infoConversation = "noaddx/conv/v1"
	aadVersion       = 0x01
	// payloadFields and filePayloadFields are the key counts of a payload without and with "f"
	payloadFields     = 3
	filePayloadFields = payloadFields + 1
)

var (
	aadMagic        = []byte("NADM")
	ErrInvalidInput = errors.New("e2e: invalid input")
	ErrBadMessage   = errors.New("e2e: message failed authentication or is malformed")
)

// Message is a decrypted payload.
type Message struct {
	Text    string // with a file, the caption: may be empty
	SentAt  int64  // sender's clock, milliseconds since epoch
	Counter int64  // sender's per-conversation counter (gaps reveal withheld messages)
	File    *File  // nil unless the message announces a file
}

// payload is the wire form; F is never set by encodePayload, so its bytes are those of
// {"t","ts","n"} exactly.
type payload struct {
	T  string       `json:"t"`
	TS int64        `json:"ts"`
	N  int64        `json:"n"`
	F  *filePayload `json:"f,omitempty"`
}

// decodeKey mirrors crypto.js b64urlDecode: alphabet whitelist, exact length, canonical bits.
// (Go's decoder would otherwise skip CR/LF, accepting a key the browser rejects.)
func decodeKey(encoded string) ([]byte, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(keySize) || !utils.IsBase64URL(encoded) {
		return nil, ErrInvalidInput
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != keySize {
		return nil, ErrInvalidInput
	}
	return raw, nil
}

// ConversationKey derives the AES-256-GCM key both peers share for one conversation.
// It is the Go reference of the one-to-one protocol, pinned against the browser by the
// interop vectors; no production code calls it: the server only relays ciphertext and the
// agent uses rooms only (decision D5, docs/architecture/agents.md).
func ConversationKey(privateKey []byte, peerPublicKey string, conversationID uuid.UUID) ([]byte, error) {
	peer, err := decodeKey(peerPublicKey)
	if err != nil || conversationID == uuid.Nil {
		return nil, ErrInvalidInput
	}
	shared, err := cryptoengine.X25519SharedSecret(privateKey, peer)
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range shared {
			shared[i] = 0
		}
	}()
	return cryptoengine.HKDFSHA256(shared, conversationID[:], []byte(infoConversation), keySize)
}

func messageAAD(conversationID, messageID uuid.UUID, senderPublicKey string) ([]byte, error) {
	sender, err := decodeKey(senderPublicKey)
	if err != nil {
		return nil, err
	}
	senderTag, err := cryptoengine.SHA256(sender)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 0, len(aadMagic)+1+16+16+len(senderTag))
	aad = append(aad, aadMagic...)
	aad = append(aad, aadVersion)
	aad = append(aad, conversationID[:]...)
	aad = append(aad, messageID[:]...)
	return append(aad, senderTag...), nil
}

// frame pads to a power-of-two size (256..4096 bytes): the ciphertext's length reveals only
// which of five size classes the message is in.
func frame(body []byte) ([]byte, error) {
	if len(body) == 0 || len(body) > maxPayloadBytes {
		return nil, ErrInvalidInput
	}
	size := padBlock
	for size < len(body)+2 {
		size *= 2
	}
	out := make([]byte, size)
	out[0] = byte(len(body) >> 8)
	out[1] = byte(len(body))
	copy(out[2:], body)
	return out, nil
}

// unframe opens any multiple of padBlock, so frames written before the power-of-two sizes
// (payloads up to 6000 bytes) stay readable.
func unframe(framed []byte) ([]byte, error) {
	if len(framed) < 2 || len(framed)%padBlock != 0 {
		return nil, ErrBadMessage
	}
	length := int(framed[0])<<8 | int(framed[1])
	if length == 0 || length+2 > len(framed) {
		return nil, ErrBadMessage
	}
	for _, b := range framed[2+length:] {
		if b != 0 {
			return nil, ErrBadMessage
		}
	}
	return framed[2 : 2+length], nil
}

// Encrypt seals one message exactly as the browser client does.
// It is the Go reference of the one-to-one protocol, pinned against the browser by the
// interop vectors; no production code calls it: the server only relays ciphertext and the
// agent uses rooms only (decision D5, docs/architecture/agents.md).
func Encrypt(key []byte, conversationID, messageID uuid.UUID, senderPublicKey, text string, sentAt, counter int64) (string, error) {
	if messageID.Version() != 4 {
		return "", ErrInvalidInput
	}
	framed, err := encodePayload(text, sentAt, counter)
	if err != nil {
		return "", err
	}
	aad, err := messageAAD(conversationID, messageID, senderPublicKey)
	if err != nil {
		return "", err
	}
	sealed, err := cryptoengine.EncryptAES256GCM(key, framed, aad)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Decrypt opens one message; any tampering with the bytes, the conversation, the message
// id or the claimed sender fails authentication.
// It is the Go reference of the one-to-one protocol, pinned against the browser by the
// interop vectors; no production code calls it: the server only relays ciphertext and the
// agent uses rooms only (decision D5, docs/architecture/agents.md).
func Decrypt(key []byte, conversationID, messageID uuid.UUID, senderPublicKey, ciphertext string) (*Message, error) {
	if !utils.IsBase64URL(ciphertext) {
		return nil, ErrBadMessage
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(ciphertext)
	if err != nil || len(sealed) < cryptoengine.GCMNonceSize+padBlock+cryptoengine.GCMTagSize {
		return nil, ErrBadMessage
	}
	aad, err := messageAAD(conversationID, messageID, senderPublicKey)
	if err != nil {
		return nil, err
	}
	framed, err := cryptoengine.DecryptAES256GCM(key, sealed, aad)
	if err != nil {
		return nil, ErrBadMessage
	}
	return decodePayload(framed)
}

// encodePayload frames {"t","ts","n"} with the exact bytes JSON.stringify produces.
func encodePayload(text string, sentAt, counter int64) ([]byte, error) {
	return framePayload(payload{T: text, TS: sentAt, N: counter})
}

// framePayload frames p with the exact bytes JSON.stringify produces.
func framePayload(p payload) ([]byte, error) {
	if p.TS <= 0 || p.N < 1 {
		return nil, ErrInvalidInput
	}
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false) // same bytes as JSON.stringify
	if err := encoder.Encode(p); err != nil {
		return nil, fmt.Errorf("e2e: encode payload: %w", err)
	}
	return frame(bytes.TrimSuffix(body.Bytes(), []byte("\n")))
}

// decodePayload accepts exactly {"t","ts","n"}, or exactly {"t","ts","n","f"} with a valid "f"
// (decodeFile), nothing more.
func decodePayload(framed []byte) (*Message, error) {
	body, err := unframe(framed)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, ErrBadMessage
	}
	fileRaw, withFile := fields["f"]
	want := payloadFields
	if withFile {
		want = filePayloadFields
	}
	if len(fields) != want {
		return nil, ErrBadMessage
	}
	var p payload
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil || p.TS <= 0 || p.N < 1 {
		return nil, ErrBadMessage
	}
	msg := &Message{Text: p.T, SentAt: p.TS, Counter: p.N}
	if withFile {
		if msg.File, err = decodeFile(fileRaw, p.F); err != nil {
			return nil, err
		}
	}
	return msg, nil
}
