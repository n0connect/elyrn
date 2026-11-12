package cryptoengine

// Sizes fixed by the algorithms themselves, in bytes. The openssl engine cannot import this
// package (this package selects it), so it keeps its own copy; select_openssl.go checks the two
// against each other at compile time.
const (
	SHA256Size    = 32               // digest and HMAC output (FIPS 180-4, RFC 2104)
	AES256KeySize = 32               // AES-256 (FIPS 197)
	GCMNonceSize  = 12               // the 96-bit IV GCM is defined for (NIST SP 800-38D §5.2.1.1)
	GCMTagSize    = 16               // the full 128-bit tag (NIST SP 800-38D §5.2.1.2)
	X25519KeySize = 32               // RFC 7748 §5
	HKDFMaxOutput = 255 * SHA256Size // L <= 255*HashLen (RFC 5869 §2.3)
)
