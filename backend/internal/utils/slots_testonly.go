//go:build test
// +build test

package utils

// FreeForTesting reports how many slots are free right now.
// SECURITY: compiled only with -tags test.
func (s *Slots) FreeForTesting() int {
	return len(s.free)
}
