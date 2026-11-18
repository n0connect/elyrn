package middleware

import (
	"context"
	"net/http"

	"elyrn/internal/database"
)

// databaseContextKey carries a request's database context when it differs from the request's
// own context (the event stream: StreamDeadline).
type databaseContextKey struct{}

// RequestDeadline gives the request ONE database deadline (finding L-03), started at the handler
// boundary: database.RequestBudget, the configured write timeout less the margin the 503 needs.
// The repositories a handler binds to the request (WithContext(DatabaseContext(r))) run every
// statement and transaction of the request under it, so a handler that runs several statements
// answers E_STORE_UNAVAILABLE (store.ErrUnavailable: a deadline hit is classified an outage)
// before net/http's write deadline cuts the connection. The per-statement defaults stay as the
// backstop of work bound to no request deadline.
//
// The deadline is the only cancellation the request's statements see: the context is detached
// from the connection's (context.WithoutCancel, keeping its values), so a client that hangs up
// or a shutdown that begins does not abort a write half-way, exactly as when statements ran
// under no request context. Not for the event stream, which lives for minutes and sets its own
// write deadlines (server.stream): it takes StreamDeadline.
func RequestDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := databaseContext(r)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}

// StreamDeadline is RequestDeadline for the event stream: the stream itself keeps the request's
// own context (its loop ends when the client goes away), while its database work (the session
// and member lookups before the first byte) runs under a context of its own, detached and under
// the same one deadline as any request, carried as a value (DatabaseContext). So a client that
// hangs up while the stream starts never turns a lookup into "context canceled", and a stalled
// database answers the stream's 503 in time, exactly as on every other route.
func StreamDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := databaseContext(r)
		defer cancel()
		next(w, withDatabaseContext(r, ctx))
	}
}

// withDatabaseContext is r carrying ctx as its database context (DatabaseContext), its own
// context untouched.
func withDatabaseContext(r *http.Request, ctx context.Context) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), databaseContextKey{}, ctx))
}

// DatabaseContext is the context a request's database work runs under: the stream's own
// (StreamDeadline), or else the request's context, which RequestDeadline already made detached
// and bounded. Every repository a request path binds goes through here.
func DatabaseContext(r *http.Request) context.Context {
	if ctx, ok := r.Context().Value(databaseContextKey{}).(context.Context); ok {
		return ctx
	}
	return r.Context()
}

// databaseContext is a request's database context: its values, never its cancellation, under
// database.RequestBudget (no deadline beyond the per-statement defaults when the budget is off).
func databaseContext(r *http.Request) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(r.Context())
	budget := database.RequestBudget()
	if budget <= 0 {
		return detached, func() {}
	}
	return context.WithTimeout(detached, budget)
}
