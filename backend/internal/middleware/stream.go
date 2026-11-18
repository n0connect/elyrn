package middleware

import (
	"context"
	"net/http"

	"elyrn/internal/apperr"
	"elyrn/internal/identity"
	"elyrn/internal/realtime"
)

// streamMarkKey carries the event stream's revocation mark (StreamRevocationMark).
type streamMarkKey struct{}

// streamMark is the revocation generation of a stream tag, read before the session was checked.
type streamMark struct {
	tag        string
	generation uint64
}

// StreamRevocationMark reads the revocation generation of the caller's stream tag BEFORE
// JWTMiddleware checks the session, for the event stream only (server.stream wires it right in
// front of JWTMiddleware). The handler hands the generation to realtime.Hub.Subscribe, which
// refuses when the tag was kicked since.
//
// Why reading it here closes the race with logout: the tag comes from the cookie's signed token
// (signature and expiry only, no database). This read happens before Authenticate reads the
// account's session epoch, in the same goroutine. A logout bumps the epoch (committed) and only
// then kicks. If Authenticate saw the old epoch, its read came before that commit, so the kick
// comes after this read: the kick bumps the generation and Subscribe refuses. If Authenticate
// saw the new epoch, the stream is refused there. Either way no stream subscribes on a session
// revoked before it subscribed.
//
// A request without a verifiable token carries no mark and goes on: JWTMiddleware refuses it.
// A hub that cannot be locked in time answers the stream's "retry later" (E_SUBSCRIBER_LIMIT),
// as Subscribe's own failures do.
func StreamRevocationMark(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := signedSession(r)
		if err != nil {
			next(w, r)
			return
		}
		tag, err := identity.StreamTag(session.UserUUID)
		if err != nil {
			apperr.WriteError(w, "StreamRevocationMark: StreamTag", err)
			return
		}
		generation, err := realtime.Default.Generation(tag)
		if err != nil {
			apperr.Write(w, "StreamRevocationMark: Generation", apperr.SubscriberLimit)
			return
		}
		mark := streamMark{tag: tag, generation: generation}
		next(w, r.WithContext(context.WithValue(r.Context(), streamMarkKey{}, mark)))
	}
}

// StreamGeneration returns the generation StreamRevocationMark read for streamTag, or false
// when the request carries no mark for that tag (the route was wired without the mark).
func StreamGeneration(r *http.Request, streamTag string) (uint64, bool) {
	mark, ok := r.Context().Value(streamMarkKey{}).(streamMark)
	if !ok || mark.tag != streamTag {
		return 0, false
	}
	return mark.generation, true
}
