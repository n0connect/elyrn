//go:build !openssl

package cryptoengine

import "elyrn/internal/cryptoengine/native"

// The default build uses the pure-Go engine (CGO_ENABLED=0 works).
var active engine = native.Engine{}
