package middleware

import (
	"context"
	"net/http"

	"elyrn/internal/database"
)

// RequestDeadline gives the request ONE database deadline (finding L-03), started at the handler
// boundary: database.RequestBudget, the configured write timeout less the margin the 503 needs.
// The repositories a handler binds to the request's context (WithContext) run every statement
// and transaction of the request under it, so a handler that runs several statements answers
// E_STORE_UNAVAILABLE (store.ErrUnavailable: a deadline hit is classified an outage) before
// net/http's write deadline cuts the connection. The per-statement defaults stay as the
// backstop of work bound to no request deadline.
//
// The deadline is the only cancellation the request's statements see: the context is detached
// from the connection's (context.WithoutCancel, keeping its values), so a client that hangs up
// or a shutdown that begins does not abort a write half-way, exactly as when statements ran
// under no request context. Not for the event stream, which lives for minutes and sets its own
// write deadlines (server.stream).
func RequestDeadline(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		budget := database.RequestBudget()
		if budget <= 0 {
			next(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), budget)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}
