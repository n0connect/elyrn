//go:build test
// +build test

package realtime

// HoldLockForTesting takes the hub's real lock and returns its release, so a test can make a
// Kick, Generation or Subscribe of the real route meet a hub that cannot be locked in time
// (each waits utils.DefaultLockTimeout, then fails).
// SECURITY: This function is ONLY available in test builds (build tag: test).
func (h *Hub) HoldLockForTesting() (release func(), err error) {
	if err := h.mu.Lock(); err != nil {
		return nil, err
	}
	return h.mu.Unlock, nil
}
