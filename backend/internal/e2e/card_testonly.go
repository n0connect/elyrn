//go:build test
// +build test

package e2e

// SealCardForTesting seals a card announcing public in this room, as any code holder can: a card
// proves the room code, not the key it announces. Tests use it to serve a second card carrying a
// member's key (a disputed seat, audit room-roster/duplicate-member-key-card-shadows-member).
// SECURITY: compiled only with -tags test.
func (r *Room) SealCardForTesting(public []byte) (string, error) {
	return r.sealCard(public)
}
