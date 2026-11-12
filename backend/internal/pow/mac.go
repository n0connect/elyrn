package pow

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"

	"elyrn/internal/cryptoengine"
)

// A challenge is authenticated instead of remembered: the salt is a MAC over everything the
// client echoes back, so the validator recomputes it from the solution and needs no stored
// entry per issued challenge (S-03: a free endpoint must not fill server memory).
//
//	salt = hex( HMAC-SHA256(secret, macLabel || challenge || be64(timestamp) || be64(ttl) || be64(difficulty))[:SaltBytes] )
//
// challenge is 32 ASCII hex characters (fixed length) and the integers are fixed-width, so the
// MAC input is unambiguous. 128 bits of tag is the salt's existing width; a forgery needs 2^128
// guesses online. The browser worker and the Go agent treat the salt as opaque hex and echo it.
const (
	// macLabel separates this MAC from any other use of the secret (domain separation)
	macLabel = "elyrn/pow-challenge/v1"
	// secretBytes: an HMAC-SHA256 key of the hash's own output length (RFC 2104 §3)
	secretBytes = cryptoengine.SHA256Size
	// sealedIntFields: timestamp, ttl and difficulty, each a big-endian int64
	sealedIntFields = 3
)

var (
	// The per-boot secret is drawn once from the engine CSPRNG at first use. A failed draw is
	// remembered, so no challenge is ever issued or accepted without a secret; a restart draws
	// a new one and every outstanding challenge stops verifying (clients fetch a fresh one).
	secretOnce sync.Once
	secret     []byte
	secretErr  error
)

// challengeSecret returns the per-boot MAC key, or the CSPRNG failure the caller answers 500.
func challengeSecret() ([]byte, error) {
	secretOnce.Do(func() {
		secret, secretErr = cryptoengine.RandomBytes(secretBytes)
	})
	if secretErr != nil {
		return nil, fmt.Errorf("pow secret: %w", secretErr)
	}
	return secret, nil
}

// challengeTag computes the salt for one challenge under key, as lowercase hex.
func challengeTag(key []byte, challenge string, timestamp, ttl int64, difficulty int) (string, error) {
	input := make([]byte, 0, len(macLabel)+len(challenge)+sealedIntFields*binary.Size(int64(0)))
	input = append(input, macLabel...)
	input = append(input, challenge...)
	input = binary.BigEndian.AppendUint64(input, uint64(timestamp))
	input = binary.BigEndian.AppendUint64(input, uint64(ttl))
	input = binary.BigEndian.AppendUint64(input, uint64(int64(difficulty)))
	mac, err := cryptoengine.HMACSHA256(key, input)
	if err != nil {
		return "", fmt.Errorf("pow tag: %w", err)
	}
	return hex.EncodeToString(mac[:SaltBytes]), nil
}

// tagMatches reports, in constant time, whether salt is the tag the server would have issued
// for the echoed fields. Errors (no secret, HMAC failure) are returned, never read as "no".
func tagMatches(challenge, salt string, timestamp, ttl int64, difficulty int) (bool, error) {
	key, err := challengeSecret()
	if err != nil {
		return false, err
	}
	want, err := challengeTag(key, challenge, timestamp, ttl, difficulty)
	if err != nil {
		return false, err
	}
	return cryptoengine.ConstantTimeEqual([]byte(want), []byte(salt)), nil
}
