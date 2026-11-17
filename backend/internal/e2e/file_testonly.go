//go:build test
// +build test

package e2e

import "github.com/google/uuid"

// SealMessageWithFileForTesting seals a room message whose payload carries "f" for file, as the
// browser does. Go never sends a file (encodePayload never emits "f"), so only tests make one:
// the agent's tests serve it to the agent, which must read it as text plus name and size.
// SECURITY: compiled only with -tags test.
func (r *Room) SealMessageWithFileForTesting(me *RoomMember, messageID uuid.UUID, recipients [][]byte, digest []byte, text string, sentAt, counter int64, file File) (string, error) {
	framed, err := framePayload(payload{T: text, TS: sentAt, N: counter, F: file.wire()})
	if err != nil {
		return "", err
	}
	return r.seal(me, roomMessageMagic, messageID, recipients, digest, framed)
}

// wire is file as "f" carries it, unvalidated: tests seal refused shapes too.
func (file File) wire() *filePayload {
	return &filePayload{I: file.ID.String(), K: encode(file.Key), S: file.Size, H: encode(file.Hash), N: file.Name}
}
