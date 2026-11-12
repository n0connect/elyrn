package middleware

import (
	"net/http"
	"runtime/debug"

	"elyrn/internal/apperr"
	"elyrn/internal/utils"
)

var recoverLogger = utils.NewLogger("RECOVER")

// Recover is the outermost link of every route chain: a handler that panics answers 500
// E_PANIC and its stack goes to the log (no request data: no path, peer or account), instead of
// net/http printing the peer address and dropping the connection. It does not wrap the
// ResponseWriter, so http.Flusher and http.NewResponseController keep working for the event
// stream. http.ErrAbortHandler is re-raised: it is net/http's own "abort quietly" signal.
// A panic after the answer began (headers sent) can only be logged; the client sees a
// truncated answer.
func Recover(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			if recovered == http.ErrAbortHandler {
				panic(recovered)
			}
			recoverLogger.Error("handler panic recovered: panic=%v stack=%s", recovered, string(debug.Stack()))
			apperr.Write(w, "Recover", apperr.Panic)
		}()
		next(w, r)
	}
}
