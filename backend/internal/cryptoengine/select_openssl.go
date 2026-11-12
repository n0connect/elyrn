//go:build openssl && cgo

package cryptoengine

import "elyrn/internal/cryptoengine/openssl"

// Built with -tags openssl: every primitive runs on libcrypto.
var active engine = openssl.Engine{}

// The openssl engine keeps its own copy of the algorithm sizes (it cannot import this
// package). Each pair must be equal: a difference in either direction is a negative constant,
// which cannot be converted to uint, so a mismatch fails the openssl build.
const (
	_ = uint(SHA256Size - openssl.SHA256Size)
	_ = uint(openssl.SHA256Size - SHA256Size)
	_ = uint(GCMNonceSize - openssl.GCMNonceSize)
	_ = uint(openssl.GCMNonceSize - GCMNonceSize)
	_ = uint(GCMTagSize - openssl.GCMTagSize)
	_ = uint(openssl.GCMTagSize - GCMTagSize)
	_ = uint(X25519KeySize - openssl.X25519KeySize)
	_ = uint(openssl.X25519KeySize - X25519KeySize)
)
