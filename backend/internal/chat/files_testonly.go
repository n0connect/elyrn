//go:build test
// +build test

package chat

// ForgetFilePartCountForTesting puts the stored-parts counter back to "not counted yet", as it is
// in a process that has not taken its first count, so a test can prove uploads fail closed.
// SECURITY: compiled only with -tags test.
func ForgetFilePartCountForTesting() error {
	return storedParts.with(func() {
		storedParts.known = false
		storedParts.stored = 0
	})
}
