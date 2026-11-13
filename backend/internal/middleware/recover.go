package middleware

import (
	"fmt"
	"net/http"
	"runtime/debug"

	"elyrn/internal/apperr"
	"elyrn/internal/database"
	"elyrn/internal/utils"
)

var recoverLogger = utils.NewLogger("RECOVER")

// Recover is the outermost link of every route chain: a handler that panics answers 500
// E_PANIC and the panic goes to the log as its Go type (panicSummary) and its stack as
// function names and source lines (utils.StackFrames); no request data: no path, peer,
// account, panic text or argument value. That is instead of net/http printing the peer address
// and dropping the connection. It does not wrap the ResponseWriter, so http.Flusher and
// http.NewResponseController keep working for the event stream. http.ErrAbortHandler is
// re-raised: it is net/http's own "abort quietly" signal. A panic after the answer began
// (headers sent) can only be logged; the client sees a truncated answer.
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
			recoverLogger.Error("handler panic recovered: %s stack=%s", panicSummary(recovered), utils.StackFrames(debug.Stack()))
			apperr.Write(w, "Recover", apperr.Panic)
		}()
		next(w, r)
	}
}

// panicSummary is what the log may say of a panic value: its Go type, and for a driver,
// connection or outage error its class (database.ErrorClass). Never its text: a panic value
// can be, or wrap, anything a request carried.
func panicSummary(recovered any) string {
	summary := fmt.Sprintf("type=%T", recovered)
	if err, ok := recovered.(error); ok {
		if class, ok := database.ErrorClass(err); ok {
			summary += " class=" + class
		}
	}
	return summary
}
