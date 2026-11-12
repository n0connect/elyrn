package apperr

import (
	"errors"

	"elyrn/internal/auth"
	"elyrn/internal/chat"
	"elyrn/internal/pow"
	"elyrn/internal/store"
)

// sentinels maps every service sentinel error a handler answers to its code, checked in this
// order (the order the chat handler's switch used, so an error wrapping two keeps its answer).
//
// store.ErrUnavailable is the one store error with a single meaning everywhere: the database
// failed, not the request (503, so a client retries instead of believing a key or a
// conversation is gone).
//
// store.ErrNotFound and store.ErrConflict are deliberately absent: they mean different things
// at different call sites (an absent account is "Unauthorized" for a session but a plain miss
// at login), and the chat service passes raw store errors through, which today answer 500. The
// handler that knows the context picks the code (MemberNotFound, AccountExists).
var sentinels = []struct {
	err  error
	code Code
}{
	{chat.ErrInvalidInput, InvalidInput},
	{chat.ErrNotFound, NotFound},
	{chat.ErrLimitReached, LimitReached},
	{chat.ErrConflict, Conflict},
	{chat.ErrRoomFull, RoomFull},
	{chat.ErrStale, RosterChanged}, // the roster changed since the sender fetched it: refetch, re-encrypt
	{chat.ErrIdentityUnset, IdentityUnset},
	{chat.ErrForbidden, Forbidden},
	{auth.ErrBusy, Argon2Busy},
	{auth.ErrPendingStoreFull, PendingStoreFull},
	{pow.ErrRateLimited, PoWRateLimited},
	{pow.ErrCapacity, PoWCapacity},
	{pow.ErrInvalidSolution, PoWInvalid},
	{store.ErrUnavailable, StoreUnavailable},
}

// CodeOf returns the code a sentinel error (or one wrapping it) is answered with.
func CodeOf(err error) (Code, bool) {
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.code, true
		}
	}
	return 0, false
}
